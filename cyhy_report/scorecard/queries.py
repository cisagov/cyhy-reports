'''
Queries used by the scorecard report
'''

from cyhy.db import database

def open_ticket_age_pl(current_datetime):
    return [
           {'$match': {'open':True, 'false_positive':False}},
           {'$project': {'owner':True,
                         'severity':'$details.severity',
                         'open_ticket_duration':{'$subtract': [current_datetime, '$time_opened']}}
                        },
           {'$group': {'_id': {'severity':'$severity',
                               'owner':'$owner'},
                       'avg_open_ticket_duration_msec':{'$avg':'$open_ticket_duration'},
                       'max_open_ticket_duration_msec':{'$max':'$open_ticket_duration'},
                       'open_ticket_count':{'$sum':1}
                      }
           }
           ], database.TICKET_COLLECTION

def open_ticket_age_for_orgs_pl(current_datetime, parent_org, descendant_orgs):
    return [
           {'$match': {'open':True, 'false_positive':False, 'owner':{'$in':[parent_org] + descendant_orgs}}},
           {'$project': {'severity':'$details.severity',
                         'open_ticket_duration':{'$subtract': [current_datetime, '$time_opened']}}
                        },
           {'$group': {'_id': {'severity':'$severity',
                               'owner':parent_org},
                       'avg_open_ticket_duration_msec':{'$avg':'$open_ticket_duration'},
                       'max_open_ticket_duration_msec':{'$max':'$open_ticket_duration'},
                       'open_ticket_count':{'$sum':1}
                      }
           }
           ], database.TICKET_COLLECTION
           
def closed_ticket_age_pl(closed_since_date):
    return [
           {'$match': {'open':False, 'false_positive':False, 'time_closed':{'$gte':closed_since_date}}},
           {'$project': {'owner':True,
                         'severity':'$details.severity',
                         'duration_to_close':{'$subtract': ['$time_closed', '$time_opened']}}
                        },
           {'$group': {'_id': {'severity':'$severity',
                               'owner':'$owner'},
                       'avg_duration_to_close_msec':{'$avg':'$duration_to_close'},
                       'max_duration_to_close_msec':{'$max':'$duration_to_close'},
                       'closed_ticket_count':{'$sum':1}
                      }
           }
           ], database.TICKET_COLLECTION

def closed_ticket_age_for_orgs_pl(closed_since_date, parent_org, descendant_orgs):
    return [
           {'$match': {'open':False, 'false_positive':False, 
            'time_closed':{'$gte':closed_since_date}, 'owner':{'$in':[parent_org] + descendant_orgs}}},
           {'$project': {'severity':'$details.severity',
                         'duration_to_close':{'$subtract': ['$time_closed', '$time_opened']}}
                        },
           {'$group': {'_id': {'severity':'$severity',
                               'owner':parent_org},
                       'avg_duration_to_close_msec':{'$avg':'$duration_to_close'},
                       'max_duration_to_close_msec':{'$max':'$duration_to_close'},
                       'closed_ticket_count':{'$sum':1}
                      }
           }
           ], database.TICKET_COLLECTION
