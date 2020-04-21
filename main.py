from stix2 import TAXIICollectionSource, Filter, Bundle
from taxii2client.v20 import Collection
import os

# Initialize dictionary to hold Enterprise ATT&CK content
attack = {}

# Establish TAXII2 Collection instance for Enterprise ATT&CK collection
ENTERPRISE_ATTCK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
PRE_ATTCK = "062767bd-02d2-4b72-84ba-56caef0f8658"
MOBILE_ATTCK = "2f669986-b40b-4423-b720-4396ca6a462b"

collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")

# Supply the collection to TAXIICollection
tc_source = TAXIICollectionSource(collection)

# Create filters to retrieve content from Enterprise ATT&CK based on type
filter_objs = {"techniques": Filter("type", "=", "attack-pattern"),
               "mitigations": Filter("type", "=", "course-of-action"),
               "groups": Filter("type", "=", "intrusion-set"),
               "malware": Filter("type", "=", "malware"),
               "tools": Filter("type", "=", "tool"),
               "relationships": Filter("type", "=", "relationship")
               }

searched_ids = list()
searched_objs = list()

def make_attack_dir(name):
    os.makedirs('./{0}'.format(name.replace('/', ' and ')))
    os.makedirs('./{0}/relationships'.format(name.replace('/', ' and ')))
    os.makedirs('./{0}/relationships/source_ref'.format(name.replace('/', ' and ')))
    os.makedirs('./{0}/relationships/target_ref'.format(name.replace('/', ' and ')))


# Retrieve all Enterprise ATT&CK content
for key in filter_objs:
    attack[key] = tc_source.query(filter_objs[key])


def deter_types():
    types = dict()
    for objects in attack:
        for o in attack[objects]:
            types.update({o['type']: objects})

    return types.copy()


def find_groups(target_groups):
    groups = list()
    for group in attack['groups']:
        if group['name'] in target_groups:
            if not os.path.exists('./{0}'.format(group['name'].replace('/', ' and '))):
                make_attack_dir(group['name'])
            with open('./{0}/{0}.json'.format(group['name'].replace('/', ' and ')), 'w') as f:
                f.write(group.serialize())

            groups.append(group)

    return groups.copy()

def find_relationships(obj):

    if not os.path.exists('./{0}'.format(obj['name'].replace('/', ' and '))):
        make_attack_dir(obj['name'])

    os.chdir(obj['name'].replace('/', ' and '))

    for relationship in attack['relationships']:
        if obj['id'] == relationship['source_ref']:
            with open('./relationships/source_ref/{0}.json'.format(relationship['id'].replace('/', ' and ')), 'w') as f:
                f.write(relationship.serialize())

            domain = relationship['target_ref'][:relationship['target_ref'].find('--')]
            find_match_id(relationship['target_ref'], types[domain])

        if obj['id'] == relationship['target_ref']:
            with open('./relationships/target_ref/{0}.json'.format(relationship['id'].replace('/', ' and ')), 'w') as f:
                f.write(relationship.serialize())

            domain = relationship['source_ref'][:relationship['source_ref'].find('--')]
            find_match_id(relationship['source_ref'], types[domain])

    os.chdir('../')



def find_match_id(reference_id, domain):

    for obj in attack[domain]:
        if obj['id'] == reference_id:
            print(obj)
            if not os.path.exists('./{0}'.format(obj['name'].replace('/', ' and '))):
                make_attack_dir(obj['name'])
            #
            # os.chdir(obj['name'].replace('/', ' and '))
            with open('./{0}/{0}.json'.format(obj['name'].replace('/', ' and ')), 'w') as f:
                f.write(obj.serialize())

            if obj['id'] not in searched_ids:
                searched_ids.append(obj['id'])
                searched_objs.append(obj)
                find_relationships(obj)



if __name__ == '__main__':
    target_groups = ['APT38']
    types = deter_types()

    objects = find_groups(target_groups)

    for obj in objects:
        refs = find_relationships(obj)

    bundle = Bundle(searched_objs)
    with open('{0}-bundle.json'.format('APT38'), 'w') as f:
        f.write(bundle.serialize())












