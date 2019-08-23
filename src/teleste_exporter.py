#!/usr/local/bin/python3
from aiohttp import web
from pysnmp.hlapi.asyncio import *
import asyncio
import functools

from teleste_snmp import parse_frequencies, parse_values
from teleste_snmp import proetheus_analyser_labels, prometheus_metrics
from teleste_snmp import teleste_tasklist

### SNMP ###
async def get_snmp(host,snmpEngine,poll_tasklist):

    community = CommunityData('public')
    ctx = ContextData()
    while True:

        # Initialize data dictionary used for current modem
        snmp_data = dict()

        # Initialize loop control indicating a failed poll.
        poll_error = None

        for (task_oid,task_data_key,task_format) in poll_tasklist:

            # Set the oid, used in the actual bulkCmd
            oid = task_oid

            # Initialize loop control variables, controlling when walk has to be terminated.
            end_of_current_task_oid = False

            # SNMP collector loop, breaks when done or Error
            while not end_of_current_task_oid:
                # Walk the modem
                errorIndication, errorStatus, errorIndex, varBindTable = \
                await bulkCmd(
                    snmpEngine, community,
                    UdpTransportTarget((host, 161),timeout=3,retries=2),
                    ctx, 0 , 20,
                    ObjectType(ObjectIdentity(oid)),
                    lookupMib=False,
                )
                if errorIndication:
                    # If something went wrong loclly with the poll, we set the poll_error varialbe
                    # in order for the poll of the current modem to be aborted
                    return(None,str(errorIndication))
                elif errorStatus:
                    if errorStatus:
                        # If the remote snmp agent, caused an error, we return the
                        return(None,str(errorStatus))
                else:
                    # If we did not encounter any snmp errors, we iterate over the returned rows.
                    for varBindRow in varBindTable:
                        # We only extract the "leftmost" varBind from the varBindRow, 
                        # as we only walk one OID att a time, so the returned data structure is not 2dimensional.
                        (name,value) = varBindRow[0]

                        # If the current OID is not within task_oid, we break out of the walk for the task_oid
                        if name.asTuple()[:len(task_oid)] != task_oid:
                            #print ("Out of requested OID")
                            # Indicate to outer loops that we want out.
                            end_of_current_task_oid = True

                            # Break out of the current for loop iterting the returned rows.
                            break
                        else:
                            # Populate snmp_data
                            try:
                                snmp_data[name.asTuple()[-1]][task_data_key] = task_format(value)
                            except KeyError:
                                snmp_data[name.asTuple()[-1]] = { task_data_key: task_format(value) }

                            # If we did not break out, update the oid for the next walk iteration 
                            oid = name.asTuple()

        # We are done polling the current modem, push result to output queue.
        return(snmp_data,None)

#### WEB REQUEST HANDLER ###
async def handle(request,snmpEngine):
    # Make sure we have a target_host.
    if not "target" in request.rel_url.query:
        return web.Response(status=400,text='NO IP')

    # Get the target host
    target = request.rel_url.query['target']
    print('Get snmp for host %s.' % target)

    # Retreive the SNMP data
    teleste_data,error = await get_snmp(host=target,snmpEngine=snmpEngine,poll_tasklist=teleste_tasklist())

    if error:
        return web.Response(status=400,text=error)

    output_data =  ["# HELP Unit of level in spectrumAnalyserValueTable and limit tables is 0.5 dBuV"]
    output_data += ["# TYPE spectrumAnalyserValueTable gauge"]
    output_data += prometheus_metrics(teleste_data,'spectrumAnalyserValueTable', 3)
#    output_data += prometheus_metrics(teleste_data,'spectrumAnalyserLOLOLimitTable', 4)
#    output_data += prometheus_metrics(teleste_data,'spectrumAnalyserLoLimitTable', 5)
#    output_data += prometheus_metrics(teleste_data,'spectrumAnalyserHiLimitTable', 6)
#    output_data += prometheus_metrics(teleste_data,'spectrumAnalyserHIHILimitTable', 7)

    return web.Response(text='\n'.join(output_data))

### MAIN ###

h2 = functools.partial(handle, snmpEngine=SnmpEngine())
app = web.Application()
app.add_routes([web.get('/snmp', h2),])
                

web.run_app(app)



