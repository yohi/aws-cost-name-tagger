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

    def test_signed_population_rejects_record_cost_mismatch(self):
        plan={'count':1,'records':[{'effective_usage_cost_usd':'1.25'}],
              'cur_population':sample_population(cost='1.24')}
        with self.assertRaises(ValueError):
            validate_signed_population(plan)

    def test_signed_population_accepts_matching_record_cost(self):
        plan={'count':1,'records':[{'effective_usage_cost_usd':'1.25'}],
              'cur_population':sample_population(cost='1.25')}
        self.assertEqual(validate_signed_population(plan),plan['cur_population'])

if __name__=='__main__':unittest.main()
