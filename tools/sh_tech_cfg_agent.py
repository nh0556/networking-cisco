from oslo_config import cfg                                                                                                                                                                                                                     
import oslo_messaging                                                                                                                                                                                                                           
import pprint                                                                                                                                                                                                                                   
import oslo_messaging                                                                                                                                                                                                                           


amqp_control_exchange = 'neutron'                                                                                                                                                                                                                                                
transport_url = 'rabbit://guest:guest@10.1.185.72:5672/'                                                                                                                                                                                        
# This call to get_transport will bootstrap cfg.CONF                                                                                                                                                                                            
transport = oslo_messaging.get_transport(cfg.CONF)
                                                                                                                                                                                                                                                
# dump configuration
# print ("*** initial configuration after get_transport invoked")
# res = [ {k:v} for k, v in cfg.CONF.iteritems()]
# pprint.pprint(res)
                                                                                                                                                                                                                                                
# override config settings
cfg.CONF.set_override('rabbit_host', 'localhost', 'oslo_messaging_rabbit')
cfg.CONF.set_override('rabbit_port', 5672, 'oslo_messaging_rabbit')
cfg.CONF.set_override('rabbit_userid', 'guest', 'oslo_messaging_rabbit')
cfg.CONF.set_override('rabbit_password', 'guest', 'oslo_messaging_rabbit')
cfg.CONF.set_override('rabbit_virtual_host', '/', 'oslo_messaging_rabbit')
cfg.CONF.set_override('control_exchange', amqp_control_exchange)
                                                                                                                                                                                                                                                
print ("*** rpc_client started")
                                                                                                                                                                                                                                                
# dump configuration
print ("*** oslo_cfg configuration")
res = [ {k:v} for k, v in cfg.CONF.iteritems()]
pprint.pprint(res)
                                                                                                                                                                                                                                                
#
transport = oslo_messaging.get_transport(cfg.CONF, transport_url)

target = oslo_messaging.Target(topic='cisco_cfg_agent', version='1.0')
                                                                                                                                                                                                                                                
client = oslo_messaging.RPCClient(transport, target)
                                                                                                                                                                                                                                                
context = {}
client.cast(context, 'cfg_agent_debug')
print ("*** rpc_client cast invoked")
                                                                                                                                                                                                                                                
resp = client.call(context, 'cfg_agent_debug')
print("*** rpc call response = %s" % pprint.pformat(resp))
                                                                                                                                                                                                                                                
print ("*** rpc_client finished")
