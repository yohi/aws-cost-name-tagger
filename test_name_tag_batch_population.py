import unittest
from decimal import Decimal

from name_tag_batch_population import (
    CurCostAggregate, CurBudgetExceeded, partition_cur_population,
    decimal_cost_of, classify_cur_row, exact_add, validate_signed_population,
)
from test_helpers import sample_population

class PopulationTests(unittest.TestCase):
    def test_precise_decimal_conservation_and_float_rank(self):
        a = {
            ('volume', 'vol-a', 'ap-northeast-1'): CurCostAggregate(Decimal('0.1'), 0.3),
            ('volume', 'vol-b', 'ap-northeast-1'): CurCostAggregate(Decimal('0.2'), 0.4),
            ('volume', 'vol-c', 'ap-northeast-1'): CurCostAggregate(Decimal('-0.1'), -0.1),
        }
        r = partition_cur_population(a, min_cost=0.0, max_resources=1)
        self.assertEqual(r['cur_recognized'], {'count':3,'cost_usd':'0.2'})
        self.assertEqual(r['lookup_selected'], {'count':1,'cost_usd':'0.2'})
        self.assertEqual(r['max_resources_not_inspected'], {'count':1,'cost_usd':'0.1'})
        self.assertEqual(r['below_min_cost'], {'count':1,'cost_usd':'-0.1'})
        self.assertEqual(r['selected_keys'], [('volume','vol-b','ap-northeast-1')])
    def test_decimal_original_string(self):
        self.assertEqual(exact_add(['0.1','0.2']), Decimal('0.3'))
        with self.assertRaises(ValueError): exact_add(['NaN'])
        with self.assertRaises(ValueError): exact_add(['inf'])
        with self.assertRaises(ValueError): exact_add(['1_0'])
        with self.assertRaises(ValueError): exact_add([' 1.0 '])
        self.assertEqual(decimal_cost_of({'line_item_line_item_type':'Usage', 'line_item_unblended_cost':'-0.0001'}),Decimal('-0.0001'))
    def test_accounting_budgets_and_categories(self):
        row = {'line_item_resource_id':'arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-a', 'product_region_code':'ap-northeast-1'}
        self.assertEqual(classify_cur_row(row,account='123456789012',kind_filter={'instance'},rid_class=lambda r: ('volume','vol-a','ap-northeast-1'))[0],'OUTSIDE_REQUESTED_KINDS')
        self.assertEqual(classify_cur_row(row,account='123456789012',kind_filter=None,rid_class=lambda r: ('unsupported','vol-a',None))[0],'UNSUPPORTED_KIND')
        self.assertEqual(classify_cur_row({**row,'line_item_resource_id':''},account='123456789012',kind_filter=None,rid_class=lambda r: ('unsupported','vol-a',None))[0],'UNATTRIBUTABLE_CUR')
        self.assertEqual(classify_cur_row(row,account='123456789013',kind_filter=None,rid_class=lambda r: ('volume','vol-a','ap-northeast-1'))[0],'UNATTRIBUTABLE_CUR')
        with self.assertRaises(CurBudgetExceeded): partition_cur_population({}, min_cost=0.0,max_resources=0)

    def test_excluded_supported_kind_is_classified_before_missing_region(self):
        row={'line_item_resource_id':'vol-a','product_region_code':''}

        result=classify_cur_row(
            row,account='123456789012',kind_filter={'instance'},
            rid_class=lambda resource:('volume','vol-a',None))

        self.assertEqual(result,('OUTSIDE_REQUESTED_KINDS','EXCLUDED_BY_KINDS',None))

    def test_signed_population_rejects_record_cost_mismatch(self):
        plan={'count':1,'records':[{'effective_usage_cost_usd':'1.25'}],
              'cur_population':sample_population(cost='1.24')}
        with self.assertRaises(ValueError):
            validate_signed_population(plan)

    def test_signed_population_accepts_matching_record_cost(self):
        plan={'count':1,'records':[{'effective_usage_cost_usd':'1.25'}],
              'cur_population':sample_population(cost='1.25')}
        self.assertEqual(validate_signed_population(plan),plan['cur_population'])

    def test_cost_text_rejects_exponent_and_oversized_input_before_decimal_expansion(self):
        for invalid in ('1e1000000', '9' * 10000):
            with self.subTest(invalid=invalid[:12]):
                plan={'count':1,'records':[{'effective_usage_cost_usd':'1.25'}],
                      'cur_population':sample_population(cost=invalid)}
                with self.assertRaises(ValueError):
                    validate_signed_population(plan)

    def test_zero_resource_count_requires_zero_cost(self):
        population=sample_population(count=1,cost='1')
        population['below_min_cost']={'count':0,'cost_usd':'1'}
        plan={'count':1,'records':[{'effective_usage_cost_usd':'1'}],
              'cur_population':population}
        with self.assertRaises(ValueError):
            validate_signed_population(plan)

    def test_aggregate_sum_allows_input_bound_times_maximum_rows(self):
        total=exact_add(['9' * 100, '9' * 100])
        self.assertEqual(total,Decimal('1' + '9' * 99 + '8'))
    def test_reason_details_rejected_for_unknown_billing_class(self):
        from name_tag_batch_population import validate_reason_details
        population=sample_population()
        population['unsupported_kind']={'known':False,'billing_rows':None,'cost_usd':None}
        with self.assertRaises(ValueError):
            validate_reason_details({'UNSUPPORTED_KIND:a':{'billing_rows':0,'cost_usd':'0'}},population)


class KindPrecapReportingTests(unittest.TestCase):
    """Task 9: 18-Kind pre-cap stages reconcile exactly with the global schema-2 population."""

    def test_precap_18_kind_sum_matches_global_decimal(self):
        from name_tag_batch_population import KIND_PRECAP_STAGES, validate_kind_precap
        from name_tag_kind_capabilities import REGISTRY_KINDS
        from test_name_tag_batch_report_multikind import eighteen_kind_plan
        plan=eighteen_kind_plan()
        population=plan['cur_population']
        kinds=plan['cur_population_by_kind']['kinds']
        self.assertEqual(set(kinds),set(REGISTRY_KINDS))
        validate_kind_precap(plan,population)
        for stage in KIND_PRECAP_STAGES:
            with self.subTest(stage=stage):
                per_kind=[Decimal(kinds[kind][stage]['cost_usd']) for kind in REGISTRY_KINDS]
                self.assertEqual(sum(kinds[kind][stage]['count'] for kind in REGISTRY_KINDS),
                                 population[stage]['count'])
                self.assertEqual(exact_add(per_kind),Decimal(population[stage]['cost_usd']))
                # 32-place Decimals: a 28-digit context sum would round and disagree.
                self.assertGreater(len(population['lookup_selected']['cost_usd']),28)
        self.assertEqual(population['cur_recognized']['count'],54)
        self.assertEqual(population['lookup_selected']['count'],18)

    def test_below_threshold_and_uninspected_nonvolume_included(self):
        from name_tag_batch_report import build_batch_dry_run
        from name_tag_batch_state import build_batch_review_projection
        from test_name_tag_batch_identity_projection import (
            INSTANCE, PlanFixture, R, SNAP, VOL, VOL_ARN, cur_row, info_for)
        fixture=PlanFixture('run_plan')
        fixture.addCleanup=self.addCleanup
        other_instance=INSTANCE[:-1]+'1'
        rows=[cur_row(INSTANCE,'5'),cur_row(VOL,'4'),cur_row(SNAP,'3.125'),
              cur_row(other_instance,'0.5')]
        infos={INSTANCE:info_for('instance',INSTANCE),VOL:info_for('volume',VOL_ARN)}
        doc=fixture.run_plan(rows,infos,fixture.scope(R,[VOL_ARN]),min_cost='1',max_resources='2')
        kinds=doc['cur_population_by_kind']['kinds']
        self.assertEqual(kinds['snapshot']['max_resources_not_inspected'],{'count':1,'cost_usd':'3.125'})
        self.assertEqual(kinds['snapshot']['lookup_selected'],{'count':0,'cost_usd':'0'})
        self.assertEqual(kinds['instance']['below_min_cost'],{'count':1,'cost_usd':'0.5'})
        self.assertEqual(kinds['instance']['lookup_selected'],{'count':1,'cost_usd':'5'})
        self.assertEqual(sorted(r['kind'] for r in doc['records']),['instance','volume'])
        plan_bytes=fixture.out.read_bytes()
        coverage=build_batch_dry_run(plan_bytes,build_batch_review_projection(plan_bytes))[
            'kind_capability_coverage']
        snapshot=coverage['kinds']['snapshot']
        self.assertEqual(snapshot['precap']['max_resources_not_inspected'],
                         {'count':1,'cost_usd':'3.125'})
        self.assertEqual((snapshot['selected'],snapshot['outcomes']),({'count':0,'cost_usd':'0'},{}))
        self.assertEqual(coverage['kinds']['instance']['precap']['below_min_cost'],
                         {'count':1,'cost_usd':'0.5'})
        self.assertEqual(coverage['precap_total']['cur_recognized'],{'count':4,'cost_usd':'12.625'})
        self.assertEqual(coverage['precap_total']['max_resources_not_inspected'],
                         {'count':1,'cost_usd':'3.125'})

if __name__=='__main__':unittest.main()
