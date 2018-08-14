'''
Queries used by the customer report
'''

from cyhy.db import database
from bson.son import SON

def host_latest_scan_time_span_pl(owners):
    return  [
            {'$match': {'owner':{'$in':owners},
                        'latest_scan.DONE':{'$ne':None}}},
            {'$group': {'_id':{},
                        'start_time':{'$min':'$latest_scan.DONE'},
                        'end_time':{'$max':'$latest_scan.DONE'},
                       }
            },
            ], database.HOST_COLLECTION
            
def host_latest_vulnscan_time_span_pl(owners):
    return  [
            {'$match': {'owner':{'$in':owners},
                        'state.up':True,
                        'latest_scan.VULNSCAN':{'$ne':None}}},
            {'$group': {'_id':{},
                        'start_time':{'$min':'$latest_scan.DONE'},
                        'end_time':{'$max':'$latest_scan.DONE'},
                       }
            },
            ], database.HOST_COLLECTION

def operating_system_count_pl(snapshot_oids):
    '''nmap host records contain a "name" field'''
    return  [
            {'$match': {'snapshots':{'$in':snapshot_oids}, 'name':{'$exists':True}}},
            {'$group':{'_id':   {'ip':'$ip',
                                 'operating_system':'$name',
                                 }
                      }
            },
            {'$group':{'_id':   {'operating_system':'$_id.operating_system'},
                      'count':{'$sum':1}
                      }
            },
            {'$project': {'count':True, 
                          'operating_system':{'$ifNull':['$operating_system','unknown']}
                         }
            },
            {'$sort': {'count':-1}}
            ], database.HOST_SCAN_COLLECTION

def ip_geoloc_pl(owners):
    return  [
            {'$match': {'owner':{'$in':owners}, 'state.up':True}},
            {'$group': {'_id': {'loc':'$loc'}}}
            ], database.HOST_COLLECTION
    
def services_attachment_pl(snapshot_oids):
    return  [
            {'$match': {'snapshots':{'$in':snapshot_oids}}},
            {'$project': {'_id':False,
                          'owner':True,
                          'ip_int':True,
                          'ip':True,
                          'port':True,
                          'service':'$service.name',
                         }
            },
            {'$sort':SON([('ip_int',1), ('port',1)])}
            ], database.PORT_SCAN_COLLECTION
            