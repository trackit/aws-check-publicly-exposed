import boto3
import botocore
import csv
import pprint
import argparse
import ConfigParser
import os

def get_ec2_name(tags):
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return 'NA'

def get_ec2_sg(sgs):
    res = []
    for sg in sgs:
        res.append(sg['GroupId'])
    return res

def check_if_exposed(sg):
    for r in sg['IpRanges']:
        if r['CidrIp'] == '0.0.0.0/0':
            return True
    return False

def get_port_exposed(client, region, sgs):
    res = []
    response = client.describe_security_groups(GroupIds=sgs)
    for sg in response['SecurityGroups']:
        for permission in sg['IpPermissions']:
            if check_if_exposed(permission):
                if 'FromPort' in permission and 'ToPort' in permission:
                    protocol = permission['IpProtocol']
                    if protocol == "-1":
                        protocol = "all"
                    port = "{0}/{1}".format(protocol, str(permission["FromPort"]))
                    if permission['FromPort'] != permission['ToPort']:
                        port = "{0}/{1}-{2}".format(protocol, str(permission['FromPort']), str(permission['ToPort']))
                    res.append(port)
    return res

def get_port_exposed_elb(listener_descriptions):
    res = []
    for listener in listener_descriptions:
        port = "{0}->{1}".format(listener['Listener']['LoadBalancerPort'], listener['Listener']['InstancePort'])
        res.append(port)
    return res

def get_elb_ips(session, regions, account):
    res = []
    for region in regions:
        client = session.client('elb', region_name=region)
        response = client.describe_load_balancers()
        for lb in response['LoadBalancerDescriptions']:
            res += [
                {
                    'account': account,
                    'service': 'elb',
                    'name': lb['DNSName'],
                    'sg': "NA",
                    'port_exposed': get_port_exposed_elb(lb['ListenerDescriptions'])
                }
            ]
    return res


def get_ec2_ips(session, regions, account):
    res = []
    for region in regions:
        client = session.client('ec2', region_name=region)
        reservations = client.describe_instances()
        for reservation in reservations['Reservations']:
            for instance in reservation['Instances']:
                ip_list = []
                add_to_list = False
                for interface in instance['NetworkInterfaces']:
                    for address in interface['PrivateIpAddresses']:
                        if 'Association' in address:
                            ip_list.append(address['Association']['PublicIp'])
                            add_to_list = True
                if add_to_list:
                    sg_list = get_ec2_sg(instance['SecurityGroups'])
                    res += [
                        {
                            'account': account,
                            'service': 'ec2',
                            'name': get_ec2_name(instance['Tags']),
                            'ip_addresses': ip_list,
                            'sg': sg_list,
                            'port_exposed': get_port_exposed(client, region, sg_list)
                        }
                    ]
    return res

def get_regions(session):
    client = session.client('ec2')
    regions = client.describe_regions()
    return [
        region['RegionName']
        for region in regions['Regions']
    ]

def generate_csv(data, args, header_name):
    filename = "report.csv"
    if args['o']:
        filename = args['o']
    with open(filename, 'wb') as file:
        writer = csv.DictWriter(file, header_name)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

def init():
    config_path = os.environ.get('HOME') + "/.aws/credentials"
    parser = ConfigParser.ConfigParser()
    parser.read(config_path)
    if parser.sections():
        return parser.sections()
    return []

def main():
    data = []
    parser = argparse.ArgumentParser(description="Analyse reserved instances")
    parser.add_argument("--profile", nargs="+", help="Specify AWS profile(s) (stored in ~/.aws/credentials) for the program to use")
    parser.add_argument("-o", nargs="?", help="Specify output csv file")
    parser.add_argument("--profiles-all", nargs="?", help="Run it on all profile")
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_region = os.environ.get('AWS_DEFAULT_REGION')
    args = vars(parser.parse_args())
    if 'profiles-all' in args:
        keys = init()
    elif 'profile' in args and args['profile']:
        keys = args['profile']
    else:
        keys = init()
    for key in keys:
        print 'Processing %s...' % key
        try:
            if aws_access_key and aws_secret_key and aws_region:
                session = boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)
            else:
                session = boto3.Session(profile_name=key)
            regions = get_regions(session)
            data += get_ec2_ips(session, regions, key)
            data += get_elb_ips(session, regions, key)
        except botocore.exceptions.ClientError, error:
            print error
    pprint.pprint(data)
    generate_csv(data, args, ['account', 'service', 'name', 'ip_addresses', 'sg', 'port_exposed'])


if __name__ == '__main__':
    main()
