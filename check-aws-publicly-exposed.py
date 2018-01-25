import boto3
import botocore
import csv
import pprint

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

KEYS = [
    {
        'name': '',
        'key': '',
        'secret': '',
    }
]

def generate_csv(data, header_name):
    with open('report.csv', 'wb') as file:
        writer = csv.DictWriter(file, header_name)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

def main():
    data = []
    for key in KEYS:
        print 'Processing %s...' % key['name']
        try:
            session = boto3.Session(aws_access_key_id=key['key'], aws_secret_access_key=key['secret'], region_name="us-east-1")
            regions = get_regions(session)
            data += get_ec2_ips(session, regions, key['name'])
        except botocore.exceptions.ClientError, error:
            print error
    generate_csv(data, ['account', 'service', 'name', 'ip_addresses', 'sg', 'port_exposed'])


if __name__ == '__main__':
    main()
