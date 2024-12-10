
import click
import os
import yaml

class MarkDownGenerator:
    def h1(self, text):
        return f"# {text}"
    
    def h2(self, text):
        return f"## {text}"

    def h3(self, text):
        return f"### {text}"
    
    def h4(self, text):
        return f"#### {text}"

    def h5(self, text):
        return f"##### {text}"
    
    def h6(self, text):
        return f"###### {text}"
    
    def hr(self):
        return "---"

docs_key_val = {
    'id': 'ID',
    'description': 'Description',
    'how_to_solve': 'How to solve?',
    'risks': 'Risks',
    'category': 'Category',
    'severity': 'Severity',
    'github_auto_remedy': 'Github auto-remedy support',
    'targets': 'Targets', 
    'controls': 'Standards and Controls',
    'tags': 'Tags',
    'parameters': 'Parameters'
}

md = MarkDownGenerator()

@click.command()
@click.option("--policies-dir", "-d", required=True, help="Policies directory")
@click.option("--doc-path", "-p", required=True, default=".", help="Path in which the doc will be generated")
def generate_policies_doc(policies_dir, doc_path):
    """Generate policies doc"""
    with open(os.path.join(doc_path, "policies.md"), "w") as outfile:
        for dir in os.listdir(policies_dir):
            policy = os.path.join(policies_dir, dir, "policy.yaml")
            if os.path.exists(policy):
                with open(policy) as f:
                    policy_crd = yaml.load(f, Loader=yaml.FullLoader)
                    spec = policy_crd["spec"]

                    outfile.write(f'{md.h2(spec["name"])}\n\n')
                    for k,v in docs_key_val.items():
                        if k in spec:
                            outfile.write(f'{md.h3(v)}\n{spec[k]}\n\n')
                    outfile.write(f'{md.hr()}\n\n')

if __name__ == '__main__':
    generate_policies_doc()