"""Future Batch-only exact CUR accounting; no AWS clients or legacy mutation."""
from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Mapping
import math

class CurBudgetExceeded(ValueError):
    pass

@dataclass(frozen=True)
class CurCostAggregate:
    exact_cost: Decimal
    legacy_rank_cost: float


def _canonical_decimal(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError('Nonfinite CUR monetary amount')
    if value.is_zero():
        return '0'
    s = format(value, 'f')
    return s.rstrip('0').rstrip('.') if '.' in s else s


def exact_add(values) -> Decimal:
    """Sum finite decimal values using unbounded integer coefficients, never rounded Decimal +."""
    items=[]
    for value in values:
        if isinstance(value,float):
            raise ValueError('Float is not a valid exact monetary source')
        try:
            amount=Decimal(value) if isinstance(value,(str,int,Decimal)) else None
        except InvalidOperation as e:
            raise ValueError('Invalid CUR monetary string') from e
        if amount is None or not amount.is_finite():
            raise ValueError('CUR monetary amount must be finite decimal')
        sign,digits,exp=amount.as_tuple()
        if abs(exp)>1000 or len(digits)>1000:
            raise CurBudgetExceeded('CUR decimal scale/precision budget exceeded')
        n=int(''.join(map(str,digits))) if digits else 0
        items.append((-n if sign else n,exp))
    if not items:return Decimal(0)
    scale=min(exp for _,exp in items)
    total=sum(n*10**(exp-scale) for n,exp in items)
    if total==0:return Decimal(0)
    digits=tuple(int(c) for c in str(abs(total)))
    return Decimal((1 if total<0 else 0,digits,scale))


def decimal_cost_of(row: Mapping[str,object]) -> Decimal:
    col={'Usage':'line_item_unblended_cost',
         'DiscountedUsage':'reservation_effective_cost',
         'SavingsPlanCoveredUsage':'savings_plan_savings_plan_effective_cost'}.get(row.get('line_item_line_item_type'))
    if col is None: return Decimal(0)
    value=row.get(col)
    if not isinstance(value,str) or not value.strip():
        raise ValueError('Original CUR monetary string missing')
    return exact_add([value])


def classify_cur_row(row,*,account,kind_filter,rid_class):
    """One category for an already selected account/period/USD usage row."""
    raw=row.get('line_item_resource_id')
    if not isinstance(raw,str) or not raw.strip():
        return 'UNATTRIBUTABLE_CUR','MISSING_RESOURCE_ID',None
    raw=raw.strip()
    try:
        kind,locator,arn_region=rid_class(raw)
    except (ValueError,TypeError):
        return 'UNATTRIBUTABLE_CUR','INVALID_RESOURCE_ID',None
    if kind=='unsupported':
        return 'UNSUPPORTED_KIND','UNSUPPORTED_RESOURCE_KIND',None
    if kind_filter is not None and kind not in kind_filter:
        return 'OUTSIDE_REQUESTED_KINDS','EXCLUDED_BY_KINDS',None
    if raw.startswith('arn:'):
        parts=raw.split(':',5)
        if len(parts)!=6 or (parts[4] and parts[4]!=account):
            return 'UNATTRIBUTABLE_CUR','IDENTITY_MISMATCH',None
    region=arn_region or row.get('product_region_code','')
    if not region and kind=='s3_bucket':region='global'
    if not isinstance(region,str) or not region:
        return 'UNATTRIBUTABLE_CUR','MISSING_REGION',None
    if not isinstance(locator,str) or not locator:
        return 'UNATTRIBUTABLE_CUR','INVALID_RESOURCE_ID',None
    return 'CUR_RECOGNIZED','', (kind,locator,region)


def partition_cur_population(aggregates: Mapping[tuple[str,str,str],CurCostAggregate], *, min_cost: float, max_resources: int):
    if type(max_resources) is not int or max_resources<1:
        raise CurBudgetExceeded('Invalid max-resources')
    if not isinstance(min_cost,(int,float)) or not math.isfinite(min_cost):
        raise ValueError('Invalid min-cost')
    arr=list(aggregates.items())
    if any(not isinstance(a,CurCostAggregate) or not a.exact_cost.is_finite() or not math.isfinite(a.legacy_rank_cost) for _,a in arr):
        raise ValueError('Invalid aggregate')
    # Python sort is stable; maintain legacy float membership/order and threshold.
    above=[(k,v) for k,v in sorted(arr,key=lambda t:-t[1].legacy_rank_cost) if v.legacy_rank_cost>=min_cost]
    below=[(k,v) for k,v in arr if v.legacy_rank_cost<min_cost]
    selected=above[:max_resources]
    not_inspected=above[max_resources:]
    def summary(a):return {'count':len(a),'cost_usd':_canonical_decimal(exact_add(v.exact_cost for _,v in a))}
    out={
        'cur_recognized':summary(arr), 'below_min_cost':summary(below),
        'above_min_cost':summary(above),'lookup_selected':summary(selected),
        'max_resources_not_inspected':summary(not_inspected),
        'selected_keys':[k for k,_ in selected],
    }
    assert out['cur_recognized']['count']==out['below_min_cost']['count']+out['above_min_cost']['count']
    assert out['above_min_cost']['count']==out['lookup_selected']['count']+out['max_resources_not_inspected']['count']
    return out


def validate_signed_population(plan:dict)->dict:
    """Validate required schema-2 summaries before an approvable Batch draft exists."""
    c=plan.get('cur_population')
    keys={'schema_version','accounting_complete','cur_recognized','below_min_cost','above_min_cost','lookup_selected','max_resources_not_inspected','unattributable_cur','outside_requested_kinds','unsupported_kind'}
    if type(c) is not dict or set(c)!=keys or type(c.get('schema_version')) is not int or c['schema_version']!=2 or c.get('accounting_complete') is not True:
        raise ValueError('Incomplete or unknown Batch CUR accounting')
    kind_counts=('cur_recognized','below_min_cost','above_min_cost','lookup_selected','max_resources_not_inspected')
    billing=('unattributable_cur','outside_requested_kinds','unsupported_kind')
    def cost(value):
        if type(value) is not str:
            raise ValueError('Expected exact decimal text')
        try:d=Decimal(value)
        except InvalidOperation as e:raise ValueError('Nondecimal cost') from e
        if not d.is_finite() or _canonical_decimal(d)!=value:
            raise ValueError('Noncanonical decimal cost')
        return d
    for name in kind_counts:
        record=c[name]
        if type(record) is not dict or set(record)!={'count','cost_usd'} or type(record['count']) is not int or record['count']<0:
            raise ValueError('Invalid recognized resource summary')
        cost(record['cost_usd'])
    for name in billing:
        record=c[name]
        if type(record) is not dict or set(record)!={'known','billing_rows','cost_usd'} or record['known'] is not True or type(record['billing_rows']) is not int or record['billing_rows']<0:
            raise ValueError('Unknown/incomplete billing class')
        cost(record['cost_usd'])
    def eql(a,b,c0):
        return c[a]['count']==c[b]['count']+c[c0]['count'] and cost(c[a]['cost_usd'])==exact_add((cost(c[b]['cost_usd']),cost(c[c0]['cost_usd'])))
    if not eql('cur_recognized','below_min_cost','above_min_cost') or not eql('above_min_cost','lookup_selected','max_resources_not_inspected'):
        raise ValueError('Inexact CUR population conservation')
    if type(plan.get('count')) is not int or plan['count']!=len(plan.get('records',[])) or plan['count']!=c['lookup_selected']['count']:
        raise ValueError('Selected records contradict signed population')
    return c
