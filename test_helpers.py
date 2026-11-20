"""Isolated offline fixture data only."""
def sample_population(count=1,cost='1'):
    return {
        'schema_version':2,'accounting_complete':True,
        'cur_recognized':{'count':count,'cost_usd':cost},
        'below_min_cost':{'count':0,'cost_usd':'0'},
        'above_min_cost':{'count':count,'cost_usd':cost},
        'lookup_selected':{'count':count,'cost_usd':cost},
        'max_resources_not_inspected':{'count':0,'cost_usd':'0'},
        'unattributable_cur':{'known':True,'billing_rows':0,'cost_usd':'0'},
        'outside_requested_kinds':{'known':True,'billing_rows':0,'cost_usd':'0'},
        'unsupported_kind':{'known':True,'billing_rows':0,'cost_usd':'0'},
    }
