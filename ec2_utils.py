import os
import time
import random
import pickle
import hashlib

from ConfigParser import SafeConfigParser
import boto.ec2 as ec2
import boto.vpc as vpc


# Decorator to cache validation methods, so it cached after first call
# To avoid api throttling and for better response time
def memoize(cache=dict()):
	def _memoize(func):
		def __memoize(*args, **kwargs):
			key = pickle.dumps((func.func_name, args, kwargs))
			hexd = hashlib.sha1(key).hexdigest()
			if (hexd in cache):
				return cache[hexd]['value']
			result = func(*args, **kwargs)
			cache[hexd] = {'value': result}
			return result

		return __memoize
	return _memoize

@memoize()
def validate_subnet(vpc_conn, subnet_id, subnet_cidr = "10.0.0.0/16"):
	try:
		subnet = vpc_conn.get_all_subnets(subnet_ids = [subnet_id])[0]
	except vpc_conn.ResponseError:
		# Can't get the subnet will setup a vpc and subnet and return them
		vpc = vpc_conn.create_vpc(subnet_cidr)
		vpc.add_tag("Name", value="Customers vpc")
		vpc_conn.modify_vpc_attribute(vpc.id, enable_dns_support=True)
        	vpc_conn.modify_vpc_attribute(vpc.id, enable_dns_hostnames=True)
        	igw = vpc_conn.create_internet_gateway()
        	route_table =vpc_conn.create_route_table(vpc.id)
        	vpc_conn.attach_internet_gateway(igw.id, vpc.id)
		subnet = vpc_conn.create_subnet(vpc.id, subnet_cidr)
		vpc_conn.associate_route_table(route_table.id, subnet.id)
		route = vpc_conn.create_route(route_table.id, '0.0.0.0/0', igw.id)
	return subnet
	

@memoize()
def validate_keypair(ec2_conn, key_pair_name):
	# Validate key pair exist or create one
	key_pair = ec2_conn.get_key_pair(key_pair_name)
	if not key_pair:
		key_pair_name = "temp-keypair"
		key_pair = ec2_conn.create_key_pair(temp_keypair)
		key_pair.save(os.path.join(os.getenv("HOME")))
	return key_pair

@memoize()
def validate_security_group(ec2_conn, sg_name, vpc_id):
	# Validate security group exist otherwise create one and enable ssh
	try:
		# Use filter to search for non default vpc
		sg = ec2_conn.get_all_security_groups(filters={'group-name': [sg_name],
			'vpc_id': vpc_id})[0]
	except Exception:
		# If a security group with the same name on different vpc it will fail need to make random
		sg_name = "allow-ssh %s" % random.randint(1, 10)
		sg = ec2_conn.create_security_group(sg_name, "security group allowing ssh",
			vpc_id=vpc_id)
	sg_allow_ssh = any([rule.to_port == u'22' for rule in sg.rules])
	if not sg_allow_ssh:
		try:
			sg.authorize(ip_protocol="tcp", from_port=22, to_port=22,
				cidr_ip="0.0.0.0/0")
		except ec2_conn.ResponseError:
			raise RuntimeError("Couldn't enable ssh for sg_name")
	return sg

def generate_user_data(username, password):
	# generate user data from user_data.sh
	dir_path = os.path.dirname(os.path.realpath(__file__))
	temp_user_data = os.path.join(dir_path, 'user_data.sh')
	fh = open(temp_user_data, 'r')
	script_lines = '\n'.join(fh.readlines())
	user_data = script_lines.format(username, password)
	return user_data


def read_config(config_file):
	# read configuration and return configurations dict
	parser = SafeConfigParser()
	parser.read(config_file)
	config = dict()
	config['sg_name'] = parser.get('ec2_attributes', 'sg_name')
	config['subnet_id'] = parser.get('ec2_attributes', 'subnet_id')
	config['region'] = parser.get('ec2_attributes', 'region')
	config['key_pair_name'] = parser.get('ec2_attributes', 'key_pair_name')
	config['ami_id'] = parser.get('ec2_attributes', 'ami_id')
	config['instance_type']= parser.get('ec2_attributes', 'instance_type')
	config['subnet_id'] = parser.get('ec2_attributes', 'subnet_id')
	return config 

def launch_ec2_instance(username, password):
	# Validate the parameters, and Launch the ec2 instance
	dir_path = os.path.dirname(os.path.realpath(__file__))
	ec2_cfg_file = os.path.join(dir_path,'ec2_attr.cfg')
	config = read_config(ec2_cfg_file)
	ec2_conn = ec2.connect_to_region(config['region'])
	vpc_conn = vpc.connect_to_region(config['region'])
	subnet = validate_subnet(vpc_conn, config['subnet_id'])
	sg = validate_security_group(ec2_conn, config['sg_name'], subnet.vpc_id)
	key_pair = validate_keypair(ec2_conn, config['key_pair_name'])
	interface = ec2.networkinterface.NetworkInterfaceSpecification(subnet_id=subnet.id,
		groups=[sg.id],associate_public_ip_address=True)
	interfaces = ec2.networkinterface.NetworkInterfaceCollection(interface)
	user_data = generate_user_data(username, password)
	reservation = ec2_conn.run_instances(config['ami_id'], key_name=key_pair.name,
		instance_type=config['instance_type'], network_interfaces=interfaces,
		user_data=user_data)
	instance = reservation.instances[0]
	instance.update()
	while instance.state != 'running':
		time.sleep(5)
		instance.update()
	ip_address = instance.ip_address
	return ip_address
