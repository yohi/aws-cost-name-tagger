import csv
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import aws_cost_name_tagger_v3 as t

REGION = 'ap-northeast-1'
ACCOUNT = '456720798575'
INSTANCE = 'i-0123456789abcdef0'
VOLUME = 'vol-0123456789abcdef0'
SNAPSHOT = 'snap-0123456789abcdef0'


class FakeEC2:
    def __init__(self, instance_name='scs2-prd-web-ec2', volume_name=None, attachments=None, instance_extra_tags=None):
        self.instance_name = instance_name
        self.instance_extra_tags = instance_extra_tags or []
        self.volume_name = volume_name
        self.attachments = attachments if attachments is not None else [
            {'InstanceId': INSTANCE, 'Device': '/dev/xvda', 'State': 'attached'}]
        self.writes = []

    def describe_volumes(self, VolumeIds):
        assert VolumeIds == [VOLUME]
        tags = [] if self.volume_name is None else [{'Key': 'Name', 'Value': self.volume_name}]
        return {'Volumes': [{'VolumeId': VOLUME, 'Attachments': self.attachments, 'Tags': tags}]}

    def describe_instances(self, InstanceIds):
        assert InstanceIds == [INSTANCE]
        tags = ([] if self.instance_name is None else [{'Key': 'Name', 'Value': self.instance_name}]) + self.instance_extra_tags
        return {'Reservations': [{'Instances': [{'InstanceId': INSTANCE, 'Tags': tags}]}]}

    def describe_snapshots(self, SnapshotIds, OwnerIds):
        assert SnapshotIds == [SNAPSHOT] and OwnerIds == ['self']
        return {'Snapshots': [{'SnapshotId': SNAPSHOT, 'OwnerId': ACCOUNT, 'VolumeId': VOLUME, 'Tags': []}]}

    def describe_nat_gateways(self, NatGatewayIds):
        return {'NatGateways': [{'NatGatewayId': NatGatewayIds[0], 'SubnetId': 'subnet-1', 'VpcId': 'vpc-1', 'Tags': []}]}

    def describe_subnets(self, SubnetIds):
        return {'Subnets': [{'SubnetId': 'subnet-1', 'AvailabilityZone': 'ap-northeast-1a', 'Tags': [{'Key': 'Name', 'Value': 'stock-prd-public-a'}]}]}

    def describe_vpcs(self, VpcIds):
        return {'Vpcs': [{'VpcId': 'vpc-1', 'Tags': [{'Key': 'Name', 'Value': 'stock-prd-vpc'}]}]}

    def create_tags(self, Resources, Tags):
        self.writes.append((Resources, Tags))
        if VOLUME in Resources and any(t.get("Key") == "Name" for t in Tags):
            self.volume_name = next(t["Value"] for t in Tags if t["Key"] == "Name")


class FakeSession:
    def __init__(self, clients):
        self.clients = clients
    def client(self, service, region_name=None, config=None):
        return self.clients[service]


def row_for(kind, loc, region=REGION):
    return {'kind': kind, 'locator': loc, 'region': region, 'effective_usage_cost_usd': 10.0}


class AlgorithmTests(unittest.TestCase):
    def test_prefixes(self):
        self.assertEqual(t.name_scope_prefix('scs2-prd-web-ec2'), 'scs2-prd')
        self.assertEqual(t.name_scope_prefix('coord-app-prod-alb'), 'coord-app-prod')
        self.assertEqual(t.name_scope_prefix('dh-scs2-prd-sanyo'), 'scs2-prd')
        for name in ['i-0123456789abcdef0', 'something', 'random-prod', '']:
            # random-prod is a valid explicit naming convention; don't reject.
            if name != 'random-prod':
                self.assertIsNone(t.meaningful(name))

    def test_parse_arn_and_opaque(self):
        self.assertEqual(t.rid_class('arn:aws:ec2:ap-northeast-1:123:volume/'+VOLUME), ('volume',VOLUME,REGION))
        self.assertEqual(t.rid_class('arn:aws:apigateway:ap-northeast-1::/restapis/foo/stages/prd')[0], 'apigw_stage')
        self.assertEqual(t.rid_class(INSTANCE), ('instance',INSTANCE,None))
        self.assertEqual(t.rid_class('arn:aws:quicksight:ap-northeast-1:123:user/default/alice')[0], 'unsupported')

    def test_volume_inherits_ec2_and_never_writes_in_plan(self):
        ec2=FakeEC2()
        inv=t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT)
        out=inv.resolve(row_for('volume', VOLUME))
        self.assertEqual(out['status'], 'proposed')
        self.assertEqual(out['proposed_name'], 'scs2-prd-web-ec2-ebs-xvda-abcdef0')
        self.assertEqual(out['confidence'], 'high')
        self.assertIn('EC2 '+INSTANCE, out['evidence'])
        self.assertEqual(ec2.writes, [])

    def test_volume_without_parent_or_two_owners_is_review_only(self):
        for ec2 in [FakeEC2(instance_name=None), FakeEC2(attachments=[]), FakeEC2(attachments=[
                {'InstanceId': INSTANCE, 'Device': '/dev/xvda'},
                {'InstanceId': 'i-11111111111111111', 'Device': '/dev/xvdb'}])]:
            inv=t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT)
            out=inv.resolve(row_for('volume', VOLUME))
            self.assertEqual(out['status'], 'manual_review')
            self.assertEqual(out['proposed_name'], '')

    def test_existing_nonempty_protected_and_empty_proposed(self):
        for existing, state, status in [('already-tagged', 'NONEMPTY', 'already_named'),
                                         ('', 'EMPTY', 'proposed'),
                                         (' ', 'NONEMPTY', 'already_named')]:
            with self.subTest(existing=repr(existing)):
                ec2=FakeEC2(volume_name=existing)
                inv=t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT)
                out=inv.resolve(row_for('volume', VOLUME))
                self.assertEqual((out['status'],out['name_state']), (status,state))
                self.assertEqual(out['name_key_present'], True)
                self.assertEqual(out['name_raw_value'], existing)
                self.assertEqual(bool(out['proposed_name']), status=='proposed')
                self.assertEqual(ec2.writes, [])

    def test_instance_opaque_unless_already_named(self):
        ec2=FakeEC2(instance_name=None)
        inv=t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT)
        self.assertEqual(inv.resolve(row_for('instance', INSTANCE))['status'],'manual_review')
        ec2=FakeEC2()
        inv=t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT)
        self.assertEqual(inv.resolve(row_for('instance', INSTANCE))['status'],'already_named')

    def test_instance_asg_trace_requires_manual_medium_approval(self):
        ec2=FakeEC2(instance_name=None,instance_extra_tags=[{'Key':'aws:autoscaling:groupName','Value':'scs2-prd-web-asg'}])
        inv=t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT)
        out=inv.resolve(row_for('instance', INSTANCE))
        self.assertEqual(out['status'],'proposed')
        self.assertEqual(out['confidence'],'medium')
        self.assertEqual(out['proposed_name'],'scs2-prd-web-asg-ec2-abcdef0')

    def test_snapshot_inherits_source_volume_and_ec2(self):
        inv=t.Investigator(FakeSession({'ec2': FakeEC2()}), ACCOUNT)
        out=inv.resolve(row_for('snapshot',SNAPSHOT))
        self.assertEqual(out['status'],'manual_review')
        self.assertIn('historical owner evidence required',out['evidence'])

    def test_nat_needs_vpc_and_subnet_and_is_medium(self):
        inv=t.Investigator(FakeSession({'ec2': FakeEC2()}), ACCOUNT)
        out=inv.resolve(row_for('nat','nat-0123456789abcdef0'))
        self.assertEqual(out['status'],'proposed')
        self.assertEqual(out['confidence'],'medium')
        self.assertIn('stock-prd-',out['proposed_name'])

    def test_costs_ri_effective_and_excluded_fees(self):
        cols=['bill_billing_period_start_date','line_item_usage_account_id','line_item_line_item_type',
              'line_item_resource_id','line_item_unblended_cost','reservation_effective_cost',
              'savings_plan_savings_plan_effective_cost','product_region_code','line_item_product_code','line_item_currency_code']
        sample=[
            ['2026-10-01',ACCOUNT,'Usage',INSTANCE,'15','','',REGION,'AmazonEC2','USD'],
            ['2026-10-01',ACCOUNT,'DiscountedUsage',INSTANCE,'0','10','',REGION,'AmazonEC2','USD'],
            ['2026-10-01',ACCOUNT,'Fee','','9999','','',REGION,'AmazonEC2','USD'],
            ['2026-10-01','111111111111','Usage',VOLUME,'9999','','',REGION,'AmazonEC2','USD'],
            ['2026-09-01',ACCOUNT,'Usage',VOLUME,'1000','','',REGION,'AmazonEC2','USD']]
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'x.csv.gz'
            with gzip.open(p,'wt',encoding='utf-8',newline='') as f:
                w=csv.writer(f);w.writerow(cols);w.writerows(sample)
            month,items=t.cur_candidates([str(p)],None,1,100,ACCOUNT)
            self.assertEqual(month,'2026-10')
            self.assertEqual(len(items),1)
            self.assertEqual(items[0]['effective_usage_cost_usd'],25.0)

    def test_cur_month_inference_uses_all_rows(self):
        cols=['bill_billing_period_start_date','line_item_usage_account_id','line_item_line_item_type',
              'line_item_resource_id','line_item_unblended_cost','product_region_code',
              'line_item_product_code','line_item_currency_code']
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'mixed-periods.csv.gz'
            with gzip.open(p,'wt',encoding='utf-8',newline='') as f:
                w=csv.writer(f);w.writerow(cols)
                w.writerow(['2026-09-01',ACCOUNT,'Usage',VOLUME,'9',REGION,'AmazonEC2','USD'])
                w.writerow(['2026-10-01',ACCOUNT,'Usage',INSTANCE,'12',REGION,'AmazonEC2','USD'])
            month,items=t.cur_candidates([str(p)],None,1,100,ACCOUNT)
        self.assertEqual(month,'2026-10')
        self.assertEqual([item['locator'] for item in items],[INSTANCE])

    def test_cur_without_rows_requires_explicit_month(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'empty.csv.gz'
            with gzip.open(p,'wt',encoding='utf-8',newline='') as f:
                csv.writer(f).writerow(['bill_billing_period_start_date'])
            with self.assertRaisesRegex(ValueError,'no billing rows.*--month'):
                t.cur_candidates([str(p)],None,1,100,ACCOUNT)

    def test_plan_rejects_empty_and_unknown_kind_filters(self):
        for kinds in (' , ', 'volume,unknown'):
            with self.subTest(kinds=kinds), tempfile.TemporaryDirectory() as tmp:
                args=type('Args',(),{'cur':['unused.csv.gz'],'month':'2026-10','account':ACCOUNT,
                    'min_cost':1,'max_resources':10,'kinds':kinds,'output':str(Path(tmp)/'p.json')})()
                with patch.object(t,'cur_candidates') as cur:
                    with self.assertRaisesRegex(ValueError,'kind'):
                        t.plan(args,session=object())
                    cur.assert_not_called()

    def test_plan_trims_kind_filters_and_drops_empty_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=type('Args',(),{'cur':['unused.csv.gz'],'month':'2026-10','account':ACCOUNT,
                'min_cost':1,'max_resources':10,'kinds':' volume, ,snapshot ','output':str(Path(tmp)/'p.json')})()
            session=FakeSession({'sts':FakeSTS(),'iam':FakeIAM()})
            with patch.object(t,'cur_candidates',return_value=('2026-10',[])) as cur, \
                 patch.object(t,'assert_account'), \
                 patch.object(t,'Investigator'):
                t.plan(args,session=session)
            self.assertEqual(cur.call_args.kwargs['kind_filter'],{'volume','snapshot'})

    def test_plan_preflights_outputs_before_reading_cur_or_aws(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'p.json'
            output.touch()
            args=type('Args',(),{'cur':['unused.csv.gz'],'month':'2026-10','account':ACCOUNT,
                'min_cost':1,'max_resources':10,'kinds':None,'output':str(output)})()
            with patch.object(t,'cur_candidates',return_value=('2026-10',[])) as cur:
                with self.assertRaises(SystemExit):
                    t.plan(args,session=object())
                cur.assert_not_called()

    def test_apply_yes_writes_only_after_matching_live_recheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan=Path(tmp)/'p.json';review=Path(tmp)/'review.csv';log=Path(tmp)/'audit.json'
            rec={**row_for('volume',VOLUME), 'proposed_name':'scs2-prd-web-ec2-ebs-xvda-abcdef0',
                 'status':'proposed','confidence':'high','evidence':f'EBS {VOLUME} -> attachment {INSTANCE} xvda -> EC2 {INSTANCE} Name=scs2-prd-web-ec2',
                 'write_target':VOLUME}
            rec['proposal_id']=t.proposal_key(rec)
            t.write_json(plan,{'schema_version':1,'account':ACCOUNT,'records':[rec]})
            cols=['approved','proposal_id','kind','locator','region','proposed_name']
            with review.open('w',encoding='utf-8',newline='') as f:
                w=csv.DictWriter(f,fieldnames=cols);w.writeheader();w.writerow({**{k:rec[k] for k in cols if k!='approved'}, 'approved':'YES'})
            args=type('Args',(),{'plan':str(plan),'sha256':t.sha256(plan),'review':str(review),
                  'account':ACCOUNT,'profile':None,'allow_medium':False,'max_writes':3,'log':str(log)})()
            ec2=FakeEC2()
            with patch.object(t,'build_session',return_value=FakeSession({'ec2':ec2})), patch.object(t,'assert_account'), patch.object(t,'show_aws_identity',return_value={'Arn':'arn:aws:sts::456720798575:assumed-role/readonly/test'}):
                with self.assertRaisesRegex(SystemExit, 'AWS TAG WRITES DISABLED'):
                    t.apply(args)
            self.assertEqual(ec2.writes, [])
            self.assertFalse(log.exists())

    def test_apply_stale_parent_skips_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan=Path(tmp)/'p.json';review=Path(tmp)/'review.csv';log=Path(tmp)/'audit.json'
            rec={**row_for('volume',VOLUME), 'proposed_name':'scs2-prd-web-ec2-ebs-xvda-abcdef0',
                 'status':'proposed','confidence':'high','evidence':f'EBS {VOLUME} -> attachment {INSTANCE} xvda -> EC2 {INSTANCE} Name=scs2-prd-web-ec2',
                 'write_target':VOLUME}
            rec['proposal_id']=t.proposal_key(rec)
            t.write_json(plan,{'schema_version':1,'account':ACCOUNT,'records':[rec]})
            cols=['approved','proposal_id','kind','locator','region','proposed_name']
            with review.open('w',encoding='utf-8',newline='') as f:
                w=csv.DictWriter(f,fieldnames=cols);w.writeheader();w.writerow({**{k:rec[k] for k in cols if k!='approved'}, 'approved':'YES'})
            args=type('Args',(),{'plan':str(plan),'sha256':t.sha256(plan),'review':str(review),
                  'account':ACCOUNT,'profile':None,'allow_medium':False,'max_writes':3,'log':str(log)})()
            ec2=FakeEC2(instance_name='stock-prd-app-ec2')
            with patch.object(t,'build_session',return_value=FakeSession({'ec2':ec2})), patch.object(t,'assert_account'), patch.object(t,'show_aws_identity',return_value={'Arn':'arn:aws:sts::456720798575:assumed-role/readonly/test'}):
                with self.assertRaisesRegex(SystemExit, 'AWS TAG WRITES DISABLED'):
                    t.apply(args)
            self.assertEqual(ec2.writes,[])
            self.assertFalse(log.exists())

    def test_apply_hash_guard_before_credentials_or_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan=Path(tmp)/'p.json';review=Path(tmp)/'review.csv'
            plan.write_text(json.dumps({'schema_version':1,'account':ACCOUNT,'records':[]}),encoding='utf-8')
            review.write_text('approved,proposal_id\n',encoding='utf-8')
            args=type('Args',(),{'plan':str(plan),'sha256':'a'*64,'review':str(review),'account':ACCOUNT})()
            with self.assertRaises(SystemExit):t.apply(args)



class FakeRDS:
    def __init__(self, instance_name=None, parent_name='scs2-prd-db-cluster',
                 parent_members=None, parent_product='scs2', child_product='scs2'):
        self.instance_name=instance_name
        self.parent_name=parent_name
        self.parent_product=parent_product
        self.child_product=child_product
        self.parent_members=parent_members if parent_members is not None else ['scs2-prd-db-cluster-instance-2']
        self.instance_id='scs2-prd-db-cluster-instance-2'
        self.calls=[]
        self.cluster_id='scs2-prd-db-cluster'
        self.cluster_rid='cluster-CQHVOI5FT5F3WZYAYMBNMH4LNU'
        self.cluster_arn=f'arn:aws:rds:{REGION}:{ACCOUNT}:cluster:{self.cluster_id}'
        self.instance_arn=f'arn:aws:rds:{REGION}:{ACCOUNT}:db:{self.instance_id}'

    def describe_db_instances(self,DBInstanceIdentifier):
        self.calls.append(('DescribeDBInstances',DBInstanceIdentifier))
        return {'DBInstances':[{'DBInstanceIdentifier':self.instance_id,'DBInstanceArn':self.instance_arn,
                                'DBClusterIdentifier':self.cluster_id, 'DbiResourceId':'db-NFWDL2MZWMYSGI3KXWDSN5FKWI'}]}

    def describe_db_clusters(self, **kwargs):
        self.calls.append(('DescribeDBClusters',kwargs))
        assert 'Filters' not in kwargs, 'case-sensitive resource-id filter would fail for lowercased CUR IDs'
        return {'DBClusters':[{'DBClusterIdentifier':self.cluster_id,'DBClusterArn':self.cluster_arn,
                 'DbClusterResourceId':self.cluster_rid,
                 'DBClusterMembers':[{'DBInstanceIdentifier':m} for m in self.parent_members]}]}

    def list_tags_for_resource(self,ResourceName):
        self.calls.append(('ListTagsForResource',ResourceName))
        if ResourceName == self.instance_arn:
            t=[{'Key':'Product','Value':self.child_product}]
            if self.instance_name is not None:t.append({'Key':'Name','Value':self.instance_name})
        else:
            t=[{'Key':'Product','Value':self.parent_product}]
            if self.parent_name is not None:t.append({'Key':'Name','Value':self.parent_name})
        return {'TagList':t}


class FakeCloudFront:
    def __init__(self, name=None, origins=None, comment='ogne', aliases=None):
        self.tags= {'Items': [] if name is None else [{'Key':'Name','Value':name}]}
        self.origins=origins or ['coord-app-prod.s3.ap-northeast-1.amazonaws.com']
        self.comment=comment
        self.aliases=aliases if aliases is not None else ['image.ogne.jp']
    def list_tags_for_resource(self,Resource):
        return {'Tags':self.tags}
    def get_distribution_config(self,Id):
        return {'DistributionConfig':{'Origins':{'Items':[{'DomainName':x} for x in self.origins]},
                                      'Comment':self.comment,'Aliases':{'Items':self.aliases}}}


class LiveEvidenceV2Tests(unittest.TestCase):
    def test_rds_child_cluster_member_ownership_and_product_tag(self):
        fake=FakeRDS()
        inv=t.Investigator(FakeSession({'rds':fake}),ACCOUNT)
        v=inv.resolve(row_for('rds_instance',fake.instance_id))
        self.assertEqual(v['status'],'proposed')
        self.assertEqual(v['confidence'],'high')
        self.assertEqual(v['proposed_name'],'scs2-prd-db-cluster-instance-2')
        self.assertIn('DBClusterMembers includes',v['evidence'])
        self.assertIn('instance Product=scs2',v['evidence'])

    def test_rds_child_fails_closed_when_not_in_cluster(self):
        fake=FakeRDS(parent_members=['scs2-prd-db-cluster-instance-1'])
        inv=t.Investigator(FakeSession({'rds':fake}),ACCOUNT)
        v=inv.resolve(row_for('rds_instance',fake.instance_id))
        self.assertEqual(v['status'],'manual_review')
        self.assertIn('not listed',v['evidence'])

    def test_rds_existing_name_skips(self):
        fake=FakeRDS(instance_name='scs2-prd-db-cluster-instance-2')
        inv=t.Investigator(FakeSession({'rds':fake}),ACCOUNT)
        v=inv.resolve(row_for('rds_instance',fake.instance_id))
        self.assertEqual(v['status'],'already_named')
        self.assertFalse(v['proposed_name'])

    def test_rds_cluster_cur_lowercase_resource_id(self):
        fake=FakeRDS(parent_name=None)
        inv=t.Investigator(FakeSession({'rds':fake}),ACCOUNT)
        v=inv.resolve(row_for('rds_cluster',fake.cluster_rid.lower()))
        self.assertEqual(v['status'],'proposed')
        self.assertEqual(v['proposed_name'],fake.cluster_id)
        self.assertIn('DbClusterResourceId',v['evidence'])

    def test_rds_product_alias_does_not_block_name_proposal(self):
        fake=FakeRDS(child_product='ogne')
        inv=t.Investigator(FakeSession({'rds':fake}),ACCOUNT)
        v=inv.resolve(row_for('rds_instance',fake.instance_id))
        self.assertEqual(v['status'],'proposed')
        self.assertEqual(v['confidence'],'high')
        self.assertEqual(v['proposed_name'],fake.instance_id)

    def test_cloudfront_origin_alias_comment_builds_usable_name(self):
        fake=FakeCloudFront()
        inv=t.Investigator(FakeSession({'cloudfront':fake}),ACCOUNT)
        arn=f'arn:aws:cloudfront::{ACCOUNT}:distribution/E2PPT5FI7AYQU8'
        v=inv.resolve(row_for('cloudfront',arn,'us-east-1'))
        self.assertEqual(v['status'],'proposed')
        self.assertEqual(v['confidence'],'medium')
        self.assertEqual(v['proposed_name'],'coord-app-prod-image-cloudfront-i7ayqu8')
        self.assertIn("'image.ogne.jp'",v['evidence'])

    def test_cloudfront_conflicting_origin_holds(self):
        fake=FakeCloudFront(origins=['scs2-prd-web.example.net','storecms2-prd-web.example.net'])
        inv=t.Investigator(FakeSession({'cloudfront':fake}),ACCOUNT)
        arn=f'arn:aws:cloudfront::{ACCOUNT}:distribution/E2PPT5FI7AYQU8'
        v=inv.resolve(row_for('cloudfront',arn,'us-east-1'))
        self.assertEqual(v['status'],'manual_review')
        self.assertFalse(v['proposed_name'])

    def test_cloudfront_existing_name_skips(self):
        fake=FakeCloudFront(name='already-valid')
        inv=t.Investigator(FakeSession({'cloudfront':fake}),ACCOUNT)
        arn=f'arn:aws:cloudfront::{ACCOUNT}:distribution/E2PPT5FI7AYQU8'
        v=inv.resolve(row_for('cloudfront',arn,'us-east-1'))
        self.assertEqual(v['status'],'already_named')

    def test_shared_scope_infrastructure_fails_closed(self):
        self.assertTrue(t.shared_scope('shared-service-prd-athena-workgroup'))
        self.assertTrue(t.shared_scope('dh-saas-data-lake-prd'))
        self.assertFalse(t.shared_scope('scs2-prd-api'))

    def test_foreign_arn_excluded_from_cur(self):
        import tempfile
        headers=['bill_billing_period_start_date','line_item_usage_account_id','line_item_line_item_type',
                 'line_item_resource_id','line_item_unblended_cost','product_region_code',
                 'line_item_product_code','line_item_currency_code']
        rows=[['2026-10-01',ACCOUNT,'Usage',f'arn:aws:cloudfront::111111111111:distribution/EXAMPLE','123','us-east-1','AmazonCloudFront','USD']]
        with tempfile.TemporaryDirectory() as tmp:
            filename=Path(tmp)/'one.gz'
            with gzip.open(filename,'wt',encoding='utf-8',newline='') as f:
                w=csv.writer(f);w.writerow(headers);w.writerows(rows)
            _,candidates=t.cur_candidates([str(filename)],'2026-10',10,100,ACCOUNT)
            self.assertEqual(candidates,[])


class SafetyRegressionV2Tests(unittest.TestCase):
    def test_s3_write_path_disabled_even_if_called_directly(self):
        inv=t.Investigator(FakeSession({}),ACCOUNT)
        with self.assertRaisesRegex(RuntimeError,'AWS TAG WRITES DISABLED'):
            inv.write_name({'kind':'s3_bucket','region':'global','write_target':'dh-scs2-prd-example',
                            'proposed_name':'scs2-prd-example-s3'})

    def test_readonly_plan_does_not_call_write_method(self):
        headers=['bill_billing_period_start_date','line_item_usage_account_id','line_item_line_item_type',
                 'line_item_resource_id','line_item_unblended_cost','product_region_code',
                 'line_item_product_code','line_item_currency_code']
        rows=[['2026-10-01',ACCOUNT,'Usage',VOLUME,'12',REGION,'AmazonEC2','USD']]
        with tempfile.TemporaryDirectory() as tmp:
            cur=Path(tmp)/'cost.csv.gz'
            with gzip.open(cur,'wt',encoding='utf-8',newline='') as f:
                w=csv.writer(f);w.writerow(headers);w.writerows(rows)
            ec2=FakeEC2()
            args=type('Args',(),{'cur':[str(cur)],'month':'2026-10','account':ACCOUNT,
                  'profile':None,'min_cost':10,'max_resources':10,'kinds':None,'products':None,
                  'output':str(Path(tmp)/'review_plan.json')})()
            with patch.object(t,'build_session',return_value=FakeSession({'ec2':ec2})), patch.object(t,'assert_account'), patch.object(t,'show_aws_identity',return_value={'Arn':'arn:aws:sts::456720798575:assumed-role/readonly/test'}):
                t.plan(args)
            self.assertEqual(ec2.writes,[])
            report=json.loads(Path(args.output).read_text())
            self.assertEqual(report['records'][0]['status'],'proposed')
            with open(Path(tmp)/'review_plan.review.csv',encoding='utf-8-sig') as f:
                approvals=list(csv.DictReader(f))
            self.assertEqual(approvals[0]['approved'],'')

    def test_rds_empty_name_is_proposed_without_aws_write(self):
        fake=FakeRDS(instance_name='')
        inv=t.Investigator(FakeSession({'rds':fake}),ACCOUNT)
        row=inv.resolve(row_for('rds_instance',fake.instance_id))
        self.assertEqual(row['status'],'proposed')
        self.assertEqual(row['name_state'],'EMPTY')
        self.assertIs(row['name_key_present'],True)
        self.assertEqual(row['name_raw_value'],'')


class FakeSTS:
    def __init__(self, account=ACCOUNT):
        self.account = account
    def get_caller_identity(self):
        return {'Account': self.account, 'UserId': 'AROATEST:interactive-test',
                'Arn': f'arn:aws:sts::{self.account}:assumed-role/review-role/interactive-test'}


class FakeIAM:
    def get_role(self, RoleName):
        assert RoleName == 'review-role'
        return {'Role': {'Arn': f'arn:aws:iam::{ACCOUNT}:role/review-role',
                         'Path': '/', 'Description': 'Test readonly metadata',
                         'MaxSessionDuration': 3600}}


class InteractiveV3Tests(unittest.TestCase):
    def args(self, tmp, **overrides):
        from argparse import Namespace
        d={'account': ACCOUNT, 'cur': [str(Path(tmp)/'test.csv.gz')], 'month': '2026-10',
           'min_cost': 1, 'max_resources': 30, 'output': str(Path(tmp)/'p.json'),
           'profile': 'my-profile', 'kinds': 'volume', 'products': None, 'mode':'dryrun',
           'login':'skip', 'max_writes':3, 'allow_medium':False}
        d.update(overrides)
        with gzip.open(d['cur'][0], 'wt', encoding='utf-8', newline='') as fh:
            w=csv.writer(fh)
            w.writerow(['bill_billing_period_start_date','line_item_usage_account_id',
                        'line_item_line_item_type','line_item_resource_id','line_item_unblended_cost',
                        'reservation_effective_cost','savings_plan_savings_plan_effective_cost',
                        'product_region_code','line_item_product_code','line_item_currency_code'])
            w.writerow(['2026-10-01',ACCOUNT,'Usage',VOLUME,'10','','',REGION,'AmazonEC2','USD'])
        return Namespace(**d)

    def test_y_mode_preflights_review_outputs_before_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp,mode='y')
            Path(tmp,'p.selected.csv').touch()
            session=FakeSession({'sts':FakeSTS(),'iam':FakeIAM()})
            with patch.object(t,'offer_remote_login',return_value=True), \
                 patch.object(t,'build_session',return_value=session), \
                 patch.object(t,'choose_mode',return_value='y'), \
                 patch.object(t,'plan') as plan:
                with self.assertRaises(SystemExit):
                    t.run_interactive(args)
                plan.assert_not_called()

    def test_identity_prints_role_and_fails_closed_on_wrong_account(self):
        fake=FakeSession({'sts':FakeSTS(), 'iam':FakeIAM()})
        from io import StringIO
        with patch('sys.stdout',new_callable=StringIO) as stream:
            ident=t.show_aws_identity(fake,ACCOUNT)
            self.assertIn('IAM Role ARN : arn:aws:iam::',stream.getvalue())
            self.assertIn('NOT VERIFIED',stream.getvalue())
        self.assertEqual(ident['Account'],ACCOUNT)
        with self.assertRaises(SystemExit):
            t.show_aws_identity(FakeSession({'sts':FakeSTS('000000000000'),'iam':FakeIAM()}),ACCOUNT)

    def test_login_remote_launches_only_after_explicit_choice(self):
        from argparse import Namespace
        args=Namespace(profile='foo',login='ask')
        with patch.object(t.sys.stdin,'isatty',return_value=True), \
             patch('builtins.input', return_value='l'), \
             patch.object(t.subprocess,'run') as run:
            self.assertTrue(t.offer_remote_login(args))
            run.assert_called_once_with(['aws','login','--remote','--profile','foo'],check=True)
        args.login='skip'
        with patch.object(t.subprocess,'run') as run:
            self.assertTrue(t.offer_remote_login(args))
            run.assert_not_called()

    def test_dryrun_produces_arn_name_csv_and_zero_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp)
            ec2=FakeEC2()
            session=FakeSession({'ec2':ec2,'sts':FakeSTS(),'iam':FakeIAM()})
            with patch.object(t,'build_session',return_value=session):
                t.run_interactive(args)
            self.assertEqual(ec2.writes,[])
            with Path(tmp,'p.result.csv').open(encoding='utf-8-sig', newline='') as fh:
                rows=list(csv.DictReader(fh))
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['result'],'dryrun_not_modified')
            self.assertEqual(rows[0]['resource_arn'],f'arn:aws:ec2:{REGION}:{ACCOUNT}:volume/{VOLUME}')
            self.assertEqual(rows[0]['name_proposed'],'scs2-prd-web-ec2-ebs-xvda-abcdef0')
            self.assertEqual(rows[0]['name_after'],'')
            self.assertTrue(Path(tmp,'p.review.csv').exists())

    def test_no_mode_cancels_before_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp,mode='n')
            ec2=FakeEC2()
            session=FakeSession({'ec2':ec2,'sts':FakeSTS(),'iam':FakeIAM()})
            with patch.object(t,'build_session',return_value=session):
                t.run_interactive(args)
            self.assertEqual(ec2.writes,[])
            self.assertFalse(Path(args.output).exists())

    def test_y_requires_tty_and_row_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp,mode='y')
            ec2=FakeEC2()
            session=FakeSession({'ec2':ec2,'sts':FakeSTS(),'iam':FakeIAM()})
            with patch.object(t,'build_session',return_value=session),patch.object(t.sys.stdin,'isatty',return_value=False):
                with self.assertRaises(SystemExit):t.run_interactive(args)
            self.assertEqual(ec2.writes,[])
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp,mode='y')
            ec2=FakeEC2()
            session=FakeSession({'ec2':ec2,'sts':FakeSTS(),'iam':FakeIAM()})
            with patch.object(t,'build_session',return_value=session), \
                 patch.object(t.sys.stdin,'isatty',return_value=True), \
                 patch('builtins.input',side_effect=['n']):
                t.run_interactive(args)
            self.assertEqual(ec2.writes,[])

    def test_y_per_item_confirm_and_final_phrase_changes_only_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp,mode='y')
            ec2=FakeEC2()
            session=FakeSession({'ec2':ec2,'sts':FakeSTS(),'iam':FakeIAM()})
            with patch.object(t,'build_session',return_value=session), \
                 patch.object(t.sys.stdin,'isatty',return_value=True), \
                 patch('builtins.input',side_effect=['y','INVALID TOKEN']):
                t.run_interactive(args)
            self.assertEqual(ec2.writes,[])
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp,mode='y')
            ec2=FakeEC2()
            session=FakeSession({'ec2':ec2,'sts':FakeSTS(),'iam':FakeIAM()})
            with patch.object(t,'build_session',return_value=session), \
                 patch.object(t.sys.stdin,'isatty',return_value=True), \
                 patch('builtins.input',side_effect=['y',f'REVIEW {ACCOUNT}']):
                t.run_interactive(args)
            self.assertEqual(ec2.writes, [])
            with Path(tmp,'p.audit.csv').open(encoding='utf-8-sig', newline='') as fh:
                result=list(csv.DictReader(fh))
            self.assertEqual(len(result),1)
            self.assertEqual(result[0]['result'],'blocked_by_safety_hold')
            self.assertEqual(result[0]['name_after'],'')
            audit=[json.loads(line) for line in Path(tmp,'p.audit.jsonl').read_text().splitlines()]
            self.assertEqual(audit[0]['event'],'review_started')
            self.assertEqual(audit[1]['event'],'write_blocked')
            self.assertEqual(audit[-1]['event'],'review_completed')
            self.assertEqual(result[0]['resource_arn'],f'arn:aws:ec2:{REGION}:{ACCOUNT}:volume/{VOLUME}')

    def test_y_never_issues_write_api_even_when_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp,mode='y')
            ec2=FakeEC2()
            with patch.object(ec2,'create_tags') as write:
                session=FakeSession({'ec2':ec2,'sts':FakeSTS(),'iam':FakeIAM()})
                with patch.object(t,'build_session',return_value=session), \
                     patch.object(t.sys.stdin,'isatty',return_value=True), \
                     patch('builtins.input',side_effect=['y',f'REVIEW {ACCOUNT}']):
                    t.run_interactive(args)
                write.assert_not_called()
            with Path(tmp,'p.audit.csv').open(encoding='utf-8-sig', newline='') as fh:
                result=list(csv.DictReader(fh))
            self.assertEqual(result[0]['result'],'blocked_by_safety_hold')


class SafetyV32Tests(unittest.TestCase):
    def test_direct_write_disabled_for_all_supported_kinds(self):
        inv=t.Investigator(FakeSession({}),ACCOUNT)
        for kind in ('instance','volume','snapshot','eni','eip','nat','endpoint',
                     'rds_cluster','rds_instance','opensearch','elbv2','apigw_stage',
                     'cloudfront','athena_workgroup','log_group','lambda','wafv2','s3_bucket'):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(RuntimeError, 'AWS TAG WRITES DISABLED'):
                    inv.write_name({'kind':kind,'region':REGION,'write_target':'x','proposed_name':'scs2-prd-x'})

    def test_ebs_product_tags_are_not_name_mapping_inputs(self):
        class FakeEC2Conflict(FakeEC2):
            def describe_volumes(self, VolumeIds):
                v=super().describe_volumes(VolumeIds)
                v['Volumes'][0]['Tags'].append({'Key':'Product','Value':'otherproduct'})
                return v
        ec2=FakeEC2Conflict(instance_extra_tags=[{'Key':'Product','Value':'scs2'}])
        result=t.Investigator(FakeSession({'ec2':ec2}),ACCOUNT).resolve(row_for('volume',VOLUME))
        self.assertEqual(result['status'],'proposed')
        self.assertEqual(result['proposed_name'],'scs2-prd-web-ec2-ebs-xvda-abcdef0')
        self.assertEqual(ec2.writes, [])

    def test_report_collision_preserves_existing_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,'report.json')
            p.write_text('existing audit')
            with self.assertRaises(FileExistsError): t.write_json(p, {'ok':True})
            self.assertEqual(p.read_text(),'existing audit')
            a=Path(tmp,'report.csv')
            a.write_text('old report')
            with self.assertRaises(FileExistsError): t.write_action_csv(a, [], ACCOUNT,mode='dryrun')
            self.assertEqual(a.read_text(),'old report')

    def test_journal_exclusive_create_does_not_truncate(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,'audit.jsonl')
            t.create_audit_journal(p)
            t.journal_event(p,{'event':'review_started'})
            before=p.read_bytes()
            with self.assertRaises(FileExistsError):t.create_audit_journal(p)
            self.assertEqual(before,p.read_bytes())

    def test_csv_formula_injection_is_neutralized(self):
        for value in ('=1+2', '  =IMPORTXML(url)', '+SUM(A1)', '-5+9', '@formula','\t=cmd','\r=bad'):
            self.assertTrue(t.safe_csv(value).startswith("'"),value)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,'out.csv')
            t.write_action_csv(p,[{'result':'dryrun','locator':'=cmd',
                'proposed_name':'+evil','evidence':'=HYPERLINK("example")'}],ACCOUNT,mode='dryrun')
            with p.open(encoding='utf-8-sig', newline='') as fh:
                row=list(csv.DictReader(fh))[0]
            self.assertTrue(row['resource_id'].startswith("'"))
            self.assertTrue(row['name_proposed'].startswith("'"))
            self.assertTrue(row['detail'].startswith("'"))

    def test_journal_fsync_failure_is_not_silent_and_keeps_previous_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,'audit.jsonl')
            t.create_audit_journal(p)
            t.journal_event(p,{'event':'write_blocked','proposal_id':'one'})
            t.journal_event(p,{'event':'write_blocked','proposal_id':'two'})
            original_bytes = p.read_bytes()
            events = [json.loads(x) for x in original_bytes.splitlines()]
            self.assertEqual([x['proposal_id'] for x in events], ['one', 'two'])
            with patch.object(t.os, 'fsync', side_effect=OSError('disk failure')):
                with self.assertRaisesRegex(OSError, 'disk failure'):
                    t.journal_event(p, {'event': 'write_blocked', 'proposal_id': 'three'})
            # The failure must not corrupt previously acknowledged bytes.
            # Do not infer persistence (or rollback) of the third append.
            observed_bytes = p.read_bytes()
            self.assertTrue(observed_bytes.startswith(original_bytes))
            self.assertEqual(
                [json.loads(line)['proposal_id'] for line in
                 observed_bytes[:len(original_bytes)].splitlines()],
                ['one', 'two'],
            )

    def test_snapshot_requires_historical_evidence_even_if_current_ec2_named(self):
        i=t.Investigator(FakeSession({'ec2':FakeEC2()}),ACCOUNT)
        result=i.resolve(row_for('snapshot',SNAPSHOT))
        self.assertEqual(result['status'],'manual_review')
        self.assertIn('historical',result['evidence'])



class SafetyV34Tests(unittest.TestCase):
    def test_new004_rejects_intermediate_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            outside=root/'outside'
            outside.mkdir()
            (root/'reports').mkdir()
            (root/'reports'/'link').symlink_to(outside, target_is_directory=True)
            target=root/'reports'/'link'/'leaf'/'plan.json'
            with self.assertRaisesRegex(ValueError, 'real directory'):
                t.write_json(target, {'secret':'AWS resource details'})
            self.assertFalse((outside/'leaf').exists())

    def test_new004_rejects_direct_and_dangling_symlink_parents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            real=root/'private'
            real.mkdir()
            (root/'link').symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                t.write_json(root/'link'/'test.json', {})
            (root/'dangling').symlink_to(root/'missing', target_is_directory=True)
            with self.assertRaises(ValueError):
                t.write_json(root/'dangling'/'leaf'/'test.json', {})
            self.assertFalse((root/'missing').exists())

    def test_new004_audit_journal_cannot_escape_via_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            real=root/'private'
            real.mkdir()
            t.create_audit_journal(real/'existing.jsonl')
            (root/'link').symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                t.create_audit_journal(root/'link'/'new.jsonl')
            self.assertFalse((real/'new.jsonl').exists())
            with self.assertRaises(ValueError):
                t.journal_event(root/'link'/'existing.jsonl', {'event':'test'})
            self.assertEqual((real/'existing.jsonl').read_text(), '')

    def test_new004_publish_rejects_symlink_destination_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            staged=root/'staged'
            staged.mkdir()
            t.write_json(staged/'plan.json', {'status':'dryrun'})
            external=root/'external'
            external.mkdir()
            (root/'outputs').mkdir()
            (root/'outputs'/'link').symlink_to(external, target_is_directory=True)
            with self.assertRaises(ValueError):
                t.publish_staged_reports([(staged/'plan.json',root/'outputs'/'link'/'plan.json')])
            self.assertFalse((external/'plan.json').exists())

    def test_new004_regular_nested_outputs_retain_private_modes(self):
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            out=root/'nested'/'deep'/'plan.json'
            t.write_json(out, {'status':'dryrun'})
            self.assertEqual(json.loads(out.read_text())['status'],'dryrun')
            self.assertEqual(stat.S_IMODE(out.stat().st_mode),0o600)
            for folder in (out.parent,out.parent.parent):
                self.assertEqual(stat.S_IMODE(folder.stat().st_mode),0o700)

    def test_new004_dotdot_path_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with self.assertRaisesRegex(ValueError, 'must not contain'):
                t.write_json(root/'one'/'..'/'plan.json', {})
            self.assertFalse((root/'plan.json').exists())

    def test_new005_one_main_entrypoint_after_all_test_classes(self):
        import ast
        source=Path(__file__).read_text()
        tree=ast.parse(source)
        guard_positions=[i for i,node in enumerate(tree.body)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name) and node.test.left.id=='__name__']
        self.assertEqual(guard_positions,[len(tree.body)-1])




class SafetyV33Tests(unittest.TestCase):
    def test_parent_product_is_not_a_name_inheritance_gate(self):
        ec2 = FakeEC2(instance_extra_tags=[{'Key':'Product','Value':'anotherproduct'}])
        item = t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT).resolve(row_for('volume', VOLUME))
        self.assertEqual(item['status'], 'proposed')
        self.assertEqual(item['confidence'], 'high')
        self.assertEqual(item['proposed_name'],'scs2-prd-web-ec2-ebs-xvda-abcdef0')
        self.assertIn('EC2 '+INSTANCE, item['evidence'])
        self.assertEqual(ec2.writes, [])

    def test_new001_parent_name_and_product_agree(self):
        ec2 = FakeEC2(instance_extra_tags=[{'Key':'Product','Value':'scs2'}])
        item = t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT).resolve(row_for('volume', VOLUME))
        self.assertEqual(item['status'], 'proposed')
        self.assertEqual(item['confidence'], 'high')
        self.assertIn('Product(observed, not validated)=scs2', item['evidence'])

    def test_parent_instance_inherits_name_without_product_alias_mapping(self):
        ec2 = FakeEC2(instance_name='storecms2-prd-front-ecs',
                      instance_extra_tags=[{'Key':'Product','Value':'storecms'}])
        inv = t.Investigator(FakeSession({'ec2': ec2}), ACCOUNT)
        self.assertEqual(inv.parent_instance(REGION,INSTANCE)[0], 'storecms2-prd-front-ecs')
        v = inv.resolve(row_for('volume',VOLUME))
        self.assertEqual(v['status'],'proposed')
        self.assertTrue(v['proposed_name'].startswith('storecms2-prd-front-ecs-ebs-'))
        self.assertEqual(ec2.writes,[])

    def test_new002_file_permissions_0600_with_umask_022(self):
        import os, stat
        old = os.umask(0o022)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)
                j=p/'audit.jsonl'
                t.create_audit_journal(j)
                t.journal_event(j,{'event':'review_started'})
                t.write_json(p/'plan.json', {'account':ACCOUNT})
                t.write_review_csv(p/'plan.review.csv', [{'kind':'volume','locator':VOLUME}])
                t.write_action_csv(p/'plan.report.csv', [], ACCOUNT, mode='plan')
                with t.private_output(p/'plan.selected.csv', newline='', encoding='utf-8-sig') as fh:
                    fh.write('test')
                for path in p.iterdir():
                    if path.is_file():
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)
        finally:
            os.umask(old)

    def test_new002_created_output_parents_are_mode_0700(self):
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            dst=Path(tmp)/'review_private'/'subdirectory'/'report.json'
            t.write_json(dst, {'kind':'safe'})
            self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o600)
            for d in (dst.parent, dst.parent.parent):
                self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)

    def test_new003_staging_write_failure_publishes_no_final_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=type('Args',(),{'cur':['unused'],'month':'2026-10','account':ACCOUNT,
              'profile':None,'min_cost':10,'max_resources':5,'kinds':None,'products':None,
              'output':str(Path(tmp)/'p.json')})()
            item={**row_for('volume', VOLUME),'status':'proposed','proposed_name':'scs2-prd-ebs',
                  'confidence':'high','write_target':VOLUME,'evidence':'dummy'}
            fake=FakeSession({'ec2':FakeEC2()})
            with patch.object(t,'cur_candidates', return_value=('2026-10',[row_for('volume',VOLUME)])), \
                 patch.object(t,'assert_account'), \
                 patch.object(t,'write_action_csv', side_effect=OSError('disk full')):
                with self.assertRaisesRegex(OSError,'disk full'):
                    t.plan(args,session=fake)
            self.assertEqual(list(Path(tmp).iterdir()),[])

    def test_new003_publish_failure_rolls_back_created_links(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            a=base/'a-stage';b=base/'b-stage'
            t.write_json(a, {'name':'a'})
            t.write_json(b, {'name':'b'})
            dst_a=base/'a.json';dst_b=base/'b.json'
            original=os.link
            count=[0]
            def fail_on_second(src,dst,**kwargs):
                count[0]+=1
                if count[0]==2:raise OSError('hardlink failure')
                return original(src,dst,**kwargs)
            with patch.object(t.os,'link',side_effect=fail_on_second):
                with self.assertRaisesRegex(OSError,'hardlink failure'):
                    t.publish_staged_reports([(a,dst_a),(b,dst_b)])
            self.assertFalse(dst_a.exists())
            self.assertFalse(dst_b.exists())

    def test_new003_preexisting_destination_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            src=base/'s'; dst=base/'d'
            t.write_json(src,{'value':'new'})
            dst.write_text('original')
            with self.assertRaises(SystemExit):
                t.publish_staged_reports([(src,dst)])
            self.assertEqual(dst.read_text(),'original')

    def test_safety_hold_apply_and_direct_write_remain_disabled(self):
        with self.assertRaises(SystemExit): t.apply(object())
        with self.assertRaises(RuntimeError):
            t.Investigator(FakeSession({}),ACCOUNT).write_name({'kind':'volume'})



class SeparateNameProductMappingTests(unittest.TestCase):
    def test_cli_has_no_product_mapping_switch(self):
        from contextlib import redirect_stderr
        from io import StringIO
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as captured:
                t.parse_cli(['plan','--account',ACCOUNT,'--cur','example.gz','--products','scs2'])
        self.assertEqual(captured.exception.code,2)

    def test_shared_names_are_not_product_classification(self):
        self.assertTrue(t.shared_scope('shared-service-prd-athena-workgroup'))
        self.assertEqual(t.name_scope_prefix('shared-service-prd-athena-workgroup'), 'shared-service-prd')

    def test_ambiguous_ownership_still_fails_closed(self):
        ec2=FakeEC2()
        inv=t.Investigator(FakeSession({'ec2':ec2}),ACCOUNT)
        result=inv.resolve(row_for('snapshot',SNAPSHOT))
        self.assertEqual(result['status'],'manual_review')
        self.assertIn('historical owner evidence required',result['evidence'])

    def test_write_name_still_disabled(self):
        inv=t.Investigator(FakeSession({}),ACCOUNT)
        with self.assertRaisesRegex(RuntimeError,'AWS TAG WRITES DISABLED'):
            inv.write_name({'kind':'volume','write_target':VOLUME,
                            'proposed_name':'storecms2-prd-web-ec2-ebs-abcdef0'})



class StrictNameStateV36Tests(unittest.TestCase):
    def test_absent_empty_nonempty_and_unknown_states(self):
        checks=[({}, 'ABSENT'),({'Product':'x'},'ABSENT'),({'Name':''},'EMPTY'),
                ({'Name':' '},'NONEMPTY'),({'Name':'\t'},'NONEMPTY'),
                ({'Name':'sample'},'NONEMPTY'),({'Name':None},'UNKNOWN'),
                ({'Name':8},'UNKNOWN'),({'name':''},'UNKNOWN'),
                ({'Name':'','NAME':''},'UNKNOWN'),(None,'UNKNOWN'),
                ([{'Key':'Name'}],'UNKNOWN'),
                ([{'Key':'Name','Value':''},{'Key':'Name','Value':'set'}],'UNKNOWN')]
        for tags,state in checks:
            with self.subTest(tags=tags):
                self.assertEqual(t.name_state(tags),state)

    def test_ebs_absent_empty_and_whitespace_are_differentiated(self):
        for tag, expected_state, expected_status in [(None,'ABSENT','proposed'),
                                                      ('','EMPTY','proposed'),
                                                      ('   ','NONEMPTY','already_named')]:
            with self.subTest(tag=tag):
                ec2=FakeEC2(volume_name=tag)
                out=t.Investigator(FakeSession({'ec2':ec2}),ACCOUNT).resolve(row_for('volume',VOLUME))
                self.assertEqual(out['name_state'],expected_state)
                self.assertIs(out['name_key_present'],tag is not None)
                self.assertEqual(out['status'],expected_status)
                self.assertEqual(out['name_raw_value'],tag)
                self.assertEqual(ec2.writes,[])

    def test_empty_name_not_guessed_when_ownership_missing(self):
        ec2=FakeEC2(volume_name='',instance_name=None)
        out=t.Investigator(FakeSession({'ec2':ec2}),ACCOUNT).resolve(row_for('volume',VOLUME))
        self.assertEqual(out['name_state'],'EMPTY')
        self.assertEqual(out['status'],'manual_review')
        self.assertEqual(out['proposed_name'],'')
        self.assertEqual(ec2.writes,[])

    def test_rds_and_cloudfront_empty_names_propose(self):
        fake=FakeRDS(instance_name='')
        i=t.Investigator(FakeSession({'rds':fake}),ACCOUNT)
        r=i.resolve(row_for('rds_instance',fake.instance_id))
        self.assertEqual((r['name_state'],r['status']),('EMPTY','proposed'))
        cf=FakeCloudFront(name='')
        arn=f'arn:aws:cloudfront::{ACCOUNT}:distribution/E2PPT5FI7AYQU8'
        c=t.Investigator(FakeSession({'cloudfront':cf}),ACCOUNT).resolve(row_for('cloudfront',arn,'us-east-1'))
        self.assertEqual((c['name_state'],c['status']),('EMPTY','proposed'))

    def test_unknown_missing_name_value_cannot_propose(self):
        class InvalidEC2(FakeEC2):
            def describe_volumes(self,VolumeIds):
                out=super().describe_volumes(VolumeIds)
                out['Volumes'][0]['Tags']=[{'Key':'Name'}]
                return out
        ec2=InvalidEC2()
        r=t.Investigator(FakeSession({'ec2':ec2}),ACCOUNT).resolve(row_for('volume',VOLUME))
        self.assertEqual(r['name_state'],'UNKNOWN')
        self.assertEqual(r['status'],'manual_review')
        self.assertEqual(r['proposed_name'],'')
        self.assertEqual(ec2.writes,[])

    def test_unknown_case_variant_tag_blocks_proposal(self):
        class InvalidEC2(FakeEC2):
            def describe_volumes(self,VolumeIds):
                out=super().describe_volumes(VolumeIds)
                out['Volumes'][0]['Tags']=[{'Key':'NAME','Value':'anything'}]
                return out
        r=t.Investigator(FakeSession({'ec2':InvalidEC2()}),ACCOUNT).resolve(row_for('volume',VOLUME))
        self.assertEqual((r['name_state'],r['status']),('UNKNOWN','manual_review'))
        self.assertFalse(r['proposed_name'])

    def test_unknown_read_error_keeps_unknown_not_absent(self):
        class BrokenEC2(FakeEC2):
            def describe_volumes(self,VolumeIds):
                raise RuntimeError('Tag lookup failed')
        r=t.Investigator(FakeSession({'ec2':BrokenEC2()}),ACCOUNT).resolve(row_for('volume',VOLUME))
        self.assertEqual(r['name_state'],'UNKNOWN')
        self.assertIsNone(r['name_key_present'])
        self.assertEqual(r['status'],'manual_review')

    def test_proposal_keys_are_distinct_from_legacy_and_by_state(self):
        base={**row_for('volume',VOLUME),'proposed_name':'scs2-prd-web-ec2-ebs-abcdef0'}
        a={**base,'name_state':'ABSENT','name_key_present':False,'name_raw_value':None}
        b={**base,'name_state':'EMPTY','name_key_present':True,'name_raw_value':''}
        legacy='|'.join(str(base[k]) for k in ('kind','locator','region','proposed_name'))
        import hashlib
        old=hashlib.sha256(legacy.encode()).hexdigest()[:20]
        self.assertNotEqual(t.proposal_key(a),t.proposal_key(b))
        self.assertNotEqual(t.proposal_key(a),old)
        self.assertNotEqual(t.proposal_key(b),old)

    def test_json_review_report_and_dryrun_preserve_state(self):
        args_cls=lambda path:type('Args',(),{'cur':[str(path/'input.csv.gz')], 'month':'2026-10',
                          'account':ACCOUNT,'profile':None,'min_cost':1,'max_resources':10,
                          'kinds':'volume','output':str(path/'p.json')})()
        headers=['bill_billing_period_start_date','line_item_usage_account_id',
                 'line_item_line_item_type','line_item_resource_id','line_item_unblended_cost',
                 'product_region_code','line_item_product_code','line_item_currency_code']
        for tag,state,key in [(None,'ABSENT',False),('','EMPTY',True),(' ','NONEMPTY',True)]:
            with self.subTest(tag=tag),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                args=args_cls(root)
                with gzip.open(root/'input.csv.gz','wt',encoding='utf-8',newline='') as fh:
                    w=csv.writer(fh);w.writerow(headers)
                    w.writerow(['2026-10-01',ACCOUNT,'Usage',VOLUME,'10',REGION,'AmazonEC2','USD'])
                ec2=FakeEC2(volume_name=tag)
                with patch.object(t,'assert_account'),patch.object(t,'build_session',return_value=FakeSession({'ec2':ec2})):
                    t.plan(args,extra_mode='dryrun')
                doc=json.loads(Path(args.output).read_text())
                rec=doc['records'][0]
                self.assertEqual(doc['schema_version'],2)
                self.assertEqual(rec['name_state'],state)
                self.assertEqual(rec['name_key_present'],key)
                self.assertEqual(rec['name_raw_value'],tag)
                for filename in ('p.review.csv','p.report.csv','p.result.csv'):
                    with (root/filename).open(encoding='utf-8-sig',newline='') as fh:
                        row=list(csv.DictReader(fh))[0]
                    self.assertEqual(row['name_state'],state)
                    self.assertEqual(row['name_key_present'],str(key))
                    self.assertEqual(row['name_raw_value'],tag or '')
                with (root/'p.result.csv').open(encoding='utf-8-sig',newline='') as fh:
                    result=list(csv.DictReader(fh))[0]['result']
                self.assertEqual(result,'already_named' if state=='NONEMPTY' else 'dryrun_not_modified')
                self.assertEqual(ec2.writes,[])

    def test_safety_hold_direct_write_and_apply_for_empty(self):
        inv=t.Investigator(FakeSession({}),ACCOUNT)
        with self.assertRaisesRegex(RuntimeError,'AWS TAG WRITES DISABLED'):
            inv.write_name({'name_state':'EMPTY','name_key_present':True,'proposed_name':'x'})
        with self.assertRaises(SystemExit):
            t.apply(object())



class OfflineSafetyBoundariesR1Tests(unittest.TestCase):
    """Existing Safety Hold contracts only; no AWS access or product changes."""

    def test_t03_malformed_tag_collection_fails_closed(self):
        malformed = [
            [None],
            [42],
            [{'Key': 12, 'Value': 'invalid'}],
            [{'Key': 'Name', 'Value': ''}, {'Key': None, 'Value': 'invalid'}],
            'not-a-tag-list',
            12,
            ('Name',),
        ]
        class MalformedVolumeEC2(FakeEC2):
            def __init__(self, bad_tags):
                super().__init__()
                self.bad_tags = bad_tags

            def describe_volumes(self, VolumeIds):
                result = super().describe_volumes(VolumeIds)
                result['Volumes'][0]['Tags'] = self.bad_tags
                return result

        for tags in malformed:
            with self.subTest(tags=tags):
                self.assertEqual(t.name_state(tags), 'UNKNOWN')
                ec2 = MalformedVolumeEC2(tags)
                result = t.Investigator(
                    FakeSession({'ec2': ec2}), ACCOUNT
                ).resolve(row_for('volume', VOLUME))
                self.assertEqual(result['name_state'], 'UNKNOWN')
                self.assertEqual(result['status'], 'manual_review')
                self.assertFalse(result['proposed_name'])
                self.assertEqual(ec2.writes, [])

    def test_t06_t07_terminal_symlink_and_dangling_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            existing = root / 'existing.txt'
            existing.write_text('unchanged', encoding='utf-8')
            missing = root / 'missing.txt'
            for label, destination in [('existing', existing), ('dangling', missing)]:
                with self.subTest(kind=label):
                    output = root / f'{label}-report.json'
                    output.symlink_to(destination)
                    with self.assertRaises(FileExistsError):
                        t.write_json(output, {'report': 'private'})
                    self.assertTrue(output.is_symlink())
                    self.assertEqual(output.readlink(), destination)
                    self.assertEqual(existing.read_text(encoding='utf-8'), 'unchanged')
                    self.assertFalse(missing.exists())

    def test_t08_mkdir_race_installs_symlink_but_cannot_redirect(self):
        import errno
        import os

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / 'outside'
            outside.mkdir()
            real_mkdir = os.mkdir
            injected = []

            def raced_mkdir(name, mode=0o777, *, dir_fd=None):
                if name == 'raced' and dir_fd is not None:
                    injected.append(name)
                    os.symlink(str(outside), name, dir_fd=dir_fd)
                    raise FileExistsError(errno.EEXIST, 'competing symlink')
                return real_mkdir(name, mode, dir_fd=dir_fd)

            with patch.object(t.os, 'mkdir', side_effect=raced_mkdir):
                with self.assertRaises(ValueError):
                    t.write_json(root / 'raced' / 'report.json', {'sensitive': True})
            self.assertEqual(injected, ['raced'])
            self.assertTrue((root / 'raced').is_symlink())
            self.assertFalse((outside / 'report.json').exists())

    def test_t10_destination_created_after_preflight_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.json'
            destination = root / 'plan.json'
            t.write_json(source, {'owner': 'publisher'})
            original_preflight = t.preflight_outputs
            injected = []

            def competing_preflight(paths):
                original_preflight(paths)
                destination.write_bytes(b'competing creator data')
                injected.append(True)

            with patch.object(t, 'preflight_outputs', side_effect=competing_preflight):
                with self.assertRaises(FileExistsError):
                    t.publish_staged_reports([(source, destination)])
            self.assertEqual(injected, [True])
            self.assertEqual(destination.read_bytes(), b'competing creator data')
            self.assertTrue(source.exists())

    def test_t11_two_publishers_cannot_both_claim_same_destination(self):
        import os
        import threading
        import time

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_a = root / 'source-a.json'
            source_b = root / 'source-b.json'
            destination = root / 'plan.json'
            t.write_json(source_a, {'publisher': 'a'})
            t.write_json(source_b, {'publisher': 'b'})
            original_link = os.link
            barrier = threading.Barrier(2)
            results = []
            lock = threading.Lock()

            def synchronized_link(src, dst, **kwargs):
                barrier.wait(timeout=10)
                return original_link(src, dst, **kwargs)

            def publisher(source):
                try:
                    t.publish_staged_reports([(source, destination)])
                    result = 'published'
                except FileExistsError:
                    result = 'collision'
                except BaseException as exc:
                    result = f'unexpected:{type(exc).__name__}:{exc}'
                with lock:
                    results.append(result)

            threads = [
                # Daemon threads cannot keep the test process alive if an
                # unexpected blocking syscall outlives the bounded joins.
                threading.Thread(target=publisher, args=(source_a,), daemon=True),
                threading.Thread(target=publisher, args=(source_b,), daemon=True),
            ]
            started = []
            with patch.object(t.os, 'link', side_effect=synchronized_link):
                try:
                    deadline = time.monotonic() + 12
                    for thread in threads:
                        thread.start()
                        started.append(thread)
                    for thread in started:
                        thread.join(timeout=max(0, deadline - time.monotonic()))
                finally:
                    # Release waiters on abnormal start/timeout; even if a
                    # worker blocks elsewhere, process shutdown stays bounded.
                    barrier.abort()
                    for thread in started:
                        thread.join(timeout=0.5)

            self.assertFalse(
                any(thread.is_alive() for thread in started),
                'publisher worker failed to stop within the bounded join',
            )
            self.assertEqual(len(started), 2)
            self.assertCountEqual(results, ['published', 'collision'])
            self.assertIn(
                destination.read_bytes(),
                (source_a.read_bytes(), source_b.read_bytes()),
            )
            self.assertTrue(source_a.exists())
            self.assertTrue(source_b.exists())

    def test_t13_destination_directory_fsync_failure_rolls_back_links(self):
        import os
        import stat

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.json'
            destination = root / 'published.json'
            t.write_json(source, {'status': 'staged'})
            expected_source_bytes = source.read_bytes()
            directory_stat = root.stat()
            original_link = os.link
            original_fsync = os.fsync
            original_unlink = os.unlink
            linked = []
            injected = []
            cleaned = []

            def tracked_link(src, dst, **kwargs):
                result = original_link(src, dst, **kwargs)
                linked.append(Path(dst).name)
                return result

            def fail_target_directory_fsync(fd):
                fd_stat = os.fstat(fd)
                is_destination_dir = (
                    stat.S_ISDIR(fd_stat.st_mode)
                    and (fd_stat.st_dev, fd_stat.st_ino)
                    == (directory_stat.st_dev, directory_stat.st_ino)
                )
                if is_destination_dir:
                    # A pre-link fsync must not satisfy this fault injection.
                    self.assertEqual(linked, [destination.name])
                    self.assertTrue(destination.is_file())
                    injected.append(fd_stat.st_ino)
                    raise OSError('forced directory fsync failure')
                return original_fsync(fd)

            def tracked_unlink(path, **kwargs):
                result = original_unlink(path, **kwargs)
                cleaned.append(Path(path).name)
                return result

            with patch.object(t.os, 'link', side_effect=tracked_link), \
                 patch.object(t.os, 'fsync', side_effect=fail_target_directory_fsync), \
                 patch.object(t.os, 'unlink', side_effect=tracked_unlink):
                with self.assertRaisesRegex(OSError, 'forced directory fsync failure'):
                    t.publish_staged_reports([(source, destination)])
            self.assertEqual(linked, [destination.name])
            self.assertEqual(len(injected), 1)
            self.assertEqual(cleaned, [destination.name])
            self.assertFalse(destination.exists())
            self.assertEqual(source.read_bytes(), expected_source_bytes)




class ReportPublishSafetyPRCTests(unittest.TestCase):
    """Offline PR-C contracts: source type, private directories and cleanup."""

    def test_t09_symlink_fifo_and_directory_sources_are_not_published(self):
        import os

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.json'
            t.write_json(source, {'report': 'source'})
            symlink = root / 'alias.json'
            symlink.symlink_to(source)
            directory = root / 'directory-source'
            directory.mkdir()
            candidates = [('symlink', symlink), ('directory', directory)]
            if hasattr(os, 'mkfifo'):
                fifo = root / 'fifo-source'
                os.mkfifo(fifo)
                candidates.append(('fifo', fifo))
            for label, invalid_source in candidates:
                with self.subTest(source_type=label):
                    destination = root / f'dest-{label}.json'
                    with self.assertRaisesRegex(ValueError, 'non-regular staged report'):
                        t.publish_staged_reports([(invalid_source, destination)])
                    self.assertFalse(destination.exists())
            self.assertTrue(symlink.is_symlink())
            self.assertEqual(source.read_bytes(), b'{\n  "report": "source"\n}\n')

    def test_t15_untrusted_output_or_staging_directory_refused(self):
        import os

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.json'
            t.write_json(source, {'report': 'source'})
            output_dir = root / 'untrusted-output'
            output_dir.mkdir()
            output_dir.chmod(0o777)
            try:
                with self.assertRaisesRegex(PermissionError, 'destination'):
                    t.publish_staged_reports([(source, output_dir / 'report.json')])
                self.assertFalse((output_dir / 'report.json').exists())
            finally:
                output_dir.chmod(0o700)

            staging_dir = root / 'untrusted-stage'
            staging_dir.mkdir()
            staged_source = staging_dir / 'source.json'
            t.write_json(staged_source, {'report': 'source'})
            staging_dir.chmod(0o777)
            try:
                with self.assertRaisesRegex(PermissionError, 'staging'):
                    t.publish_staged_reports([(staged_source, root / 'report.json')])
                self.assertFalse((root / 'report.json').exists())
            finally:
                staging_dir.chmod(0o700)
            self.assertEqual(source.read_bytes(), staged_source.read_bytes())

    def test_t14_cleanup_failure_preserves_original_and_continues(self):
        import os
        import stat

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = [root / f'source-{i}.json' for i in range(3)]
            outputs = [root / f'destination-{i}.json' for i in range(3)]
            for index, source in enumerate(sources):
                t.write_json(source, {'index': index})
            original_fsync = os.fsync
            original_unlink = os.unlink
            root_meta = root.stat()
            attempted = []

            def fail_destination_directory_fsync(fd):
                info = os.fstat(fd)
                if (stat.S_ISDIR(info.st_mode)
                        and (info.st_dev, info.st_ino) ==
                        (root_meta.st_dev, root_meta.st_ino)):
                    raise OSError('primary directory fsync failure')
                return original_fsync(fd)

            def fail_one_unlink(name, **kwargs):
                attempted.append(Path(name).name)
                if Path(name).name == outputs[1].name:
                    raise OSError('secondary cleanup failure')
                return original_unlink(name, **kwargs)

            with patch.object(t.os, 'fsync', side_effect=fail_destination_directory_fsync), \
                 patch.object(t.os, 'unlink', side_effect=fail_one_unlink):
                with self.assertRaises(t.ReportPublishCleanupError) as cm:
                    t.publish_staged_reports(list(zip(sources, outputs)))
            error = cm.exception
            self.assertIsInstance(error.primary_error, OSError)
            self.assertIn('primary directory fsync failure', str(error.primary_error))
            self.assertEqual(len(error.cleanup_errors), 1)
            self.assertEqual(error.cleanup_errors[0][0], outputs[1].name)
            self.assertIn('secondary cleanup failure', str(error.cleanup_errors[0][1]))
            self.assertEqual(error.possibly_remaining, (str(outputs[1]),))
            self.assertEqual(attempted, [p.name for p in reversed(outputs)])
            self.assertFalse(outputs[0].exists())
            self.assertTrue(outputs[1].exists())
            self.assertFalse(outputs[2].exists())
            self.assertEqual(len([p for p in sources if p.exists()]), 3)



class ReportPublishCompatibilityR1Tests(unittest.TestCase):
    """Approved Ubuntu/private-output contract and pre-AWS fail-closed checks."""

    def test_t15_a_public_output_rejected_before_cur_or_aws_for_plan_and_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = root / 'public'
            public.mkdir(mode=0o755)
            public.chmod(0o755)
            output = public / 'name_tag_plan.json'
            args = t.parse_cli([
                'plan', '--cur', 'unused.csv.gz', '--account', ACCOUNT,
                '--output', str(output),
            ])
            with patch.object(t, 'cur_candidates') as cur, \
                 patch.object(t, 'build_session') as session:
                with self.assertRaisesRegex(PermissionError, 'destination'):
                    t.plan(args)
                cur.assert_not_called()
                session.assert_not_called()

            run_args = t.parse_cli([
                'run', '--cur', 'unused.csv.gz', '--account', ACCOUNT,
                '--login', 'skip', '--mode', 'dryrun', '--output', str(output),
            ])
            with patch.object(t, 'offer_remote_login') as login, \
                 patch.object(t, 'build_session') as session:
                with self.assertRaisesRegex(PermissionError, 'destination'):
                    t.run_interactive(run_args)
                login.assert_not_called()
                session.assert_not_called()
            self.assertEqual(list(public.iterdir()), [])

    def test_t15_b_default_private_output_and_explicit_0700_are_usable(self):
        import os
        import stat

        for command in ('plan', 'run'):
            args = t.parse_cli([command, '--cur', 'unused.csv.gz', '--account', ACCOUNT])
            self.assertEqual(args.output, '.aws-cost-name-tagger/name_tag_plan.json')
        with tempfile.TemporaryDirectory() as tmp:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmp)
                args = t.parse_cli([
                    'plan', '--cur', 'unused.csv.gz', '--account', ACCOUNT,
                ])
                with patch.object(t, 'cur_candidates', return_value=('2026-10', [])), \
                     patch.object(t, 'assert_account'):
                    t.plan(args, session=FakeSession({}))
                out = Path(args.output)
                self.assertTrue(out.is_file())
                self.assertEqual(stat.S_IMODE(out.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
                self.assertTrue(out.with_suffix('.review.csv').is_file())
                self.assertTrue(out.with_suffix('.report.csv').is_file())
            finally:
                os.chdir(original_cwd)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination_dir = root / 'existing-private'
            destination_dir.mkdir(mode=0o700)
            destination_dir.chmod(0o700)
            source = root / 'source.json'
            t.write_json(source, {'ok': True})
            destination = destination_dir / 'published.json'
            t.publish_staged_reports([(source, destination)])
            self.assertEqual(destination.read_bytes(), source.read_bytes())

    def test_t15_c_owner_mismatch_denied_before_publication(self):
        import os
        import stat
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'not-owned.json'
            original_fstat = os.fstat

            def foreign_directory(fd):
                record = original_fstat(fd)
                if stat.S_ISDIR(record.st_mode):
                    return SimpleNamespace(st_uid=os.geteuid() + 1,
                                           st_mode=record.st_mode)
                return record

            with patch.object(t.os, 'fstat', side_effect=foreign_directory):
                with self.assertRaisesRegex(PermissionError, 'owned by'):
                    t.preflight_report_destination(out)
            self.assertFalse(out.exists())

    def test_t15_d_unsupported_macos_refused_before_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = t.parse_cli([
                'run', '--cur', 'unused.csv.gz', '--account', ACCOUNT,
                '--login', 'skip', '--mode', 'dryrun',
                '--output', str(Path(tmp) / 'result.json'),
            ])
            with patch.object(t.sys, 'platform', 'darwin'), \
                 patch.object(t, 'offer_remote_login') as login, \
                 patch.object(t, 'build_session') as session:
                with self.assertRaisesRegex(RuntimeError, 'only on Ubuntu Linux'):
                    t.run_interactive(args)
                login.assert_not_called()
                session.assert_not_called()
            self.assertFalse((Path(tmp) / 'result.json').exists())

    def test_t09_b_missing_posix_capabilities_fail_before_aws_or_local_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'future' / 'result.json'
            args = t.parse_cli([
                'plan', '--cur', 'unused.csv.gz', '--account', ACCOUNT,
                '--output', str(out),
            ])
            for capability, function in (
                ('supports_dir_fd', t.os.stat),
                ('supports_follow_symlinks', t.os.link),
            ):
                with self.subTest(capability=capability, function=function.__name__):
                    saved = set(getattr(t.os, capability))
                    saved.discard(function)
                    with patch.object(t.os, capability, saved), \
                         patch.object(t, 'cur_candidates') as cur, \
                         patch.object(t, 'build_session') as session:
                        with self.assertRaisesRegex(RuntimeError, 'requires'):
                            t.plan(args)
                        cur.assert_not_called()
                        session.assert_not_called()
                    self.assertFalse(out.parent.exists())

    def test_t14_b_multiple_cleanup_errors_preserve_primary_and_all_attempts(self):
        import os
        import stat

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = [root / f'source-{i}.json' for i in range(4)]
            outputs = [root / f'destination-{i}.json' for i in range(4)]
            for index, source in enumerate(sources):
                t.write_json(source, {'index': index})
            original_fsync, original_unlink = os.fsync, os.unlink
            root_meta = root.stat()
            attempted = []
            failed = {outputs[0].name, outputs[2].name}

            def fail_destination_fsync(fd):
                info = os.fstat(fd)
                if (stat.S_ISDIR(info.st_mode)
                        and (info.st_dev, info.st_ino) ==
                        (root_meta.st_dev, root_meta.st_ino)):
                    raise OSError('primary fsync failure')
                return original_fsync(fd)

            def fail_two_unlinks(name, **kwargs):
                attempted.append(Path(name).name)
                if Path(name).name in failed:
                    raise OSError(f"cleanup failure: {Path(name).name}")
                return original_unlink(name, **kwargs)

            with patch.object(t.os, 'fsync', side_effect=fail_destination_fsync), \
                 patch.object(t.os, 'unlink', side_effect=fail_two_unlinks):
                with self.assertRaises(t.ReportPublishCleanupError) as captured:
                    t.publish_staged_reports(list(zip(sources, outputs)))

            error = captured.exception
            self.assertIn('primary fsync failure', str(error.primary_error))
            self.assertIs(error.__cause__, error.primary_error)
            self.assertEqual(len(error.cleanup_errors), 2)
            self.assertEqual({name for name, _ in error.cleanup_errors}, failed)
            self.assertEqual({str(p) for p in outputs if p.exists()},
                             set(error.possibly_remaining))
            self.assertEqual(attempted, [p.name for p in reversed(outputs)])
            self.assertTrue(all(p.exists() for p in sources))



if __name__ == '__main__':
    unittest.main(verbosity=2)
