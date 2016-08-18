from oslo_config import cfg
import oslo_messaging
import pprint

host = 'mitaka'
amqp_control_exchange = 'neutron'
#transport_url = 'rabbit://guest:guest@10.1.185.72:5672/'
#transport_url = 'rabbit://guest:guest@172.29.74.138:5672/'
transport_url = 'rabbit://stackrabbit:simple@172.29.74.138:5672/'
# This call to get_transport will bootstrap cfg.CONF
transport = oslo_messaging.get_transport(cfg.CONF)

# override config settings
cfg.CONF.set_override('rabbit_host', 'localhost', 'oslo_messaging_rabbit')
cfg.CONF.set_override('rabbit_port', 5672, 'oslo_messaging_rabbit')
cfg.CONF.set_override('rabbit_userid', 'guest', 'oslo_messaging_rabbit')
cfg.CONF.set_override('rabbit_password', 'guest', 'oslo_messaging_rabbit')
cfg.CONF.set_override('rabbit_virtual_host', '/', 'oslo_messaging_rabbit')
cfg.CONF.set_override('control_exchange', amqp_control_exchange)

print ("*** rpc_client started")
print ("*** oslo_cfg configuration")
res = [{k: v} for k, v in cfg.CONF.iteritems()]
pprint.pprint(res)


transport = oslo_messaging.get_transport(cfg.CONF, transport_url)

target_topic = "%s.%s" % ('cisco_cfg_agent_l3_routing', host)

target = oslo_messaging.Target(topic=target_topic, version='1.1')

client = oslo_messaging.RPCClient(transport, target)

context = {}
client.cast(context, 'cfg_agent_debug')
print ("*** rpc_client cast invoked")

resp = client.call(context, 'cfg_agent_debug')
print("*** rpc call response = %s" % resp)

