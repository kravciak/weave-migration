
import click
import os
import yaml

def check_standard(controls, standard):
    for control in controls:
        if standard in control:
            return True
    return False

@click.command()
@click.option("--policies-dir", "-d", required=True, help="Policies directory")
@click.option("--csv-path", "-p", required=True, default=".", help="Path in which the csv file will be generated")
def generate_datastudio_csv(policies_dir, csv_path):
    """Generate datastudio csv file"""
    with open(os.path.join(csv_path, "datastudio.csv"), "w") as outfile:
        for dir in os.listdir(policies_dir):
            policy = os.path.join(policies_dir, dir, "policy.yaml")
            if os.path.exists(policy):
                with open(policy) as f:
                    policy_crd = yaml.load(f, Loader=yaml.FullLoader)
                    spec = policy_crd["spec"]
                    data_record = ""

                    # category
                    data_record += f"'{spec['category']}',"

                    # entites
                    entities = ""
                    for entity in spec["targets"]["kinds"]:
                        entities += entity + ","
                    data_record += f"'{entities[:-1]}',"

                    # name
                    data_record += f"'{spec['name']}',"

                    # github auto remedy
                    data_record += "'True'" if spec.get("github_actions") else "'False'" + ","
                    
                    # has exclusions
                    has_exclusions = False
                    if spec.get("parameters"):
                        for param in spec["parameters"]:
                            if "exclude" in param["name"]:
                                data_record += "'True'" + ","
                                has_exclusions = True
                                break
                    if not has_exclusions:
                        data_record += "'False'" + ","

                    # default tag
                    data_record += "'True'" if spec.get("tags") and "default" in spec["tags"] else "'False'" + ","
                    
                    # standards
                    if spec.get("controls"):
                        for standard in ["pci-dss", "cis-benchmark", "mitre-attack", "nist800-190", "hipaa", "soc2-type-i", "gdpr"]:
                            data_record += "'True'" if check_standard(spec["controls"], standard) else "'False'"
                            data_record += ","
                    else:
                        for i in range(7):
                            data_record += "'False',"

                    outfile.write(f'{data_record[:-1]}\n') # [:-1] for last comma

if __name__ == '__main__':
    generate_datastudio_csv()