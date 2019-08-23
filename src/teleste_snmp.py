from pysnmp.hlapi import *
from itertools import repeat

ifmib_ifname = (1,3,6,1,2,1,31,1,1,1,1)
ifmib_iftype = (1,3,6,1,2,1,2,2,1,3)
ifmib_ifalias = (1,3,6,1,2,1,31,1,1,1,18)



# TELESTE
# spectrumAnalyserIndex               = (1,3,6,1,4,1,3715,100,2,10,1,1)
spectrumAnalyserType                = (1,3,6,1,4,1,3715,100,2,10,1,2)
spectrumAnalyserChannelTable        = (1,3,6,1,4,1,3715,100,2,10,1,6)
spectrumAnalyserValueTable          = (1,3,6,1,4,1,3715,100,2,10,1,8)
spectrumAnalyserChannelTableName    = (1,3,6,1,4,1,3715,100,2,10,1,5)
spectrumAnalyserHIHILimitTable      = (1,3,6,1,4,1,3715,100,2,10,1,9)
spectrumAnalyserHiLimitTable        = (1,3,6,1,4,1,3715,100,2,10,1,10)
spectrumAnalyserLoLimitTable        = (1,3,6,1,4,1,3715,100,2,10,1,11)
spectrumAnalyserLOLOLimitTable      = (1,3,6,1,4,1,3715,100,2,10,1,12)

def walk(snmp_engine,target,community,oid):
    for (errorIndication, errorStatus, errorIndex, varBind) in bulkCmd(
            snmp_engine, community, target,
            ContextData(), 0, 20,
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
            # This somehow makes the last OIP repeat 2 times, must read docs.
            #lexicographicMode=False,
        ):

        if errorIndication:
            yield (errorIndication,None,None)
        elif errorStatus:
            yield (str(errorStatus),None,None)
        else:
            (name,value) = varBind[0]
            if not oid == name.asTuple()[:len(oid)]:
                break
            else:
                if len(name.asTuple()[len(oid):]) == 1:
                    yield (None,name.asTuple()[-1],value)    
                else:
                    yield (None,name.asTuple()[len(oid):],value)
        
def parse_frequencies(data):
    l = len(data)
    out_list = []

    for index in range(0,l,2):
        val = ((data[index]<<8) + data[index+1]) / 4.0
        out_list.append(val)

    return out_list 

def parse_values(data):
    l = len(data)
    out_list = []

    for index in range(0,l):
        val = data[index]
        out_list.append(val)

    return(out_list)


def walk_tasklist(ip,community,collect_tasks):
    community = CommunityData(community)
    snmp_engine = SnmpEngine()
    target = UdpTransportTarget((ip, 161),timeout=5,retries=3)

    collected_data = dict()

    for (task_oid,task_data_key,task_format) in collect_tasks:
        # print ("Colleting: %s" % task_data_key )
        for (error,index,value) in walk(snmp_engine,target,community,task_oid):
            if error:
                return False,error

            # In the pyton spirit. Just do it and ask for forgiveness.
            try:
                collected_data[index][task_data_key] = task_format(value)
            except KeyError:
                collected_data[index] = { task_data_key: task_format(value) }

    return collected_data,None


def proetheus_analyser_labels(current_data_row):
    label_list = [ 
        ('spectrumAnalyserIndex',current_data_row[0]),
        ('spectrumAnalyserType',current_data_row[1]),
        ('spectrumAnalyserChannelTable', current_data_row[2]),
        ('spectrumAnalyserChannelTableHz', int(current_data_row[2] * 1000000) ),
    ]

    return ",".join(["%s=\"%s\"" % (label,value) for (label,value) in label_list])


def prometheus_metrics(teleste_data,metric_name,value_index):
    # Iterate over each index.
    for current_index,v in teleste_data.items():

        # Zip the Frequency, measured level, type  and the threshold limits.
        # Per measured frequency.
        analyser_channel_table = zip (
            # Limit repeats, to preven accidental infinte blowup.
            repeat(current_index,times=100),
            repeat(v['type_table'],times=100),
            v['channel_table'],
            v['value_table'],
#            v['lolo_limit'],v['lo_limit'],v['hi_limit'],v['hihi_limit'],
        )

        for current_data_row in analyser_channel_table:
            yield ("%s{%s} %s" % (metric_name,proetheus_analyser_labels(current_data_row),current_data_row[value_index]))


def teleste_tasklist():
    # Teleste OIDS
    spectrumAnalyserType                = (1,3,6,1,4,1,3715,100,2,10,1,2)
    spectrumAnalyserChannelTable        = (1,3,6,1,4,1,3715,100,2,10,1,6)
    spectrumAnalyserValueTable          = (1,3,6,1,4,1,3715,100,2,10,1,8)
    spectrumAnalyserChannelTableName    = (1,3,6,1,4,1,3715,100,2,10,1,5)
#    spectrumAnalyserHIHILimitTable      = (1,3,6,1,4,1,3715,100,2,10,1,9)
#    spectrumAnalyserHiLimitTable        = (1,3,6,1,4,1,3715,100,2,10,1,10)
#    spectrumAnalyserLoLimitTable        = (1,3,6,1,4,1,3715,100,2,10,1,11)
#    spectrumAnalyserLOLOLimitTable      = (1,3,6,1,4,1,3715,100,2,10,1,12)

    collect_tasks = [
        [ spectrumAnalyserType, 'type_table', lambda x: str(x)] ,
        [ spectrumAnalyserChannelTable, 'channel_table', lambda x: parse_frequencies(x) ],
        [ spectrumAnalyserValueTable, 'value_table', lambda x: parse_values(x) ],
        # Thresholds
#        [ spectrumAnalyserLOLOLimitTable, 'lolo_limit', lambda x: parse_values(x) ],
#        [ spectrumAnalyserLoLimitTable, 'lo_limit', lambda x: parse_values(x) ],
#        [ spectrumAnalyserHiLimitTable, 'hi_limit', lambda x: parse_values(x) ],
#        [ spectrumAnalyserHIHILimitTable, 'hihi_limit', lambda x: parse_values(x) ],
       ]

    return collect_tasks

def poll_teleste():
    teleste_data,error = walk_tasklist('172.16.22.86','public',teleste_tasklist())

    if error:
        print(error)
        exit()

    print ("# HELP Unit of level in spectrumAnalyserValueTable and limit tables is 0.5 dBuV")
    print ("# TYPE gauge")
    print('\n'.join(prometheus_metrics(teleste_data,'spectrumAnalyserValueTable', 3)))
    #print('\n'.join(prometheus_metrics(teleste_data,'spectrumAnalyserLOLOLimitTable', 4)))
    #print('\n'.join(prometheus_metrics(teleste_data,'spectrumAnalyserLoLimitTable', 5)))
    #print('\n'.join(prometheus_metrics(teleste_data,'spectrumAnalyserHiLimitTable', 6)))
    #print('\n'.join(prometheus_metrics(teleste_data,'spectrumAnalyserHIHILimitTable', 7)))
    print()




# MAIN  not used anyore, this is a module for external usage.
if __name__ == "__main__":
    poll_teleste()








