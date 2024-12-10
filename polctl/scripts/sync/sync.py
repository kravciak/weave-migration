import click
import os
from policy import PolicySyncer
from template import TemplateSyncer
from standard import StandardSyncer
from category import CategorySyncer
from client import MAGALIX_ACCOUNT, POLICIES_SVC_URL

@click.group()
def sync():
    """Sync script that syncs policies, templates, standards, controls and categories to Magalix policies service"""
    pass

@sync.command()
@click.option("--policies-dir", "-d", required=True, help="Policies directory")
@click.option("--magalix-account", "-a", required=True, default=MAGALIX_ACCOUNT, help="Magalix account ID")
@click.option("--policies-service", "-s", required=True, default=POLICIES_SVC_URL, help="Policies Service url")
@click.option("--new-only", is_flag=True, default=False, help="Sync only new policies")
@click.option("--sync-deleted", is_flag=True, default=False, help="Sync deleted policies")
def policies(policies_dir, magalix_account, policies_service, new_only, sync_deleted):
    """Sync policies"""
    syncer = PolicySyncer(policies_service=policies_service, magalix_account=magalix_account, policies_dir=policies_dir)
    syncer.sync(new_only=new_only, sync_deleted=sync_deleted)

@sync.command()
@click.option("--templates-dir", "-d", required=True, help="Templates directory")
@click.option("--magalix-account", "-a", required=True, default=MAGALIX_ACCOUNT, help="Magalix account ID")
@click.option("--policies-service", "-s", required=True, default=POLICIES_SVC_URL, help="Policies Service url")
@click.option("--new-only", is_flag=True, default=False, help="Sync only new templates")
@click.option("--sync-deleted", is_flag=True, default=False, help="Sync deleted templates")
def templates(templates_dir, magalix_account, policies_service, new_only, sync_deleted):
    """Sync templates"""
    syncer = TemplateSyncer(policies_service=policies_service, magalix_account=magalix_account, templates_dir=templates_dir)
    syncer.sync(new_only=new_only, sync_deleted=sync_deleted)

@sync.command()
@click.option("--standards-dir", "-d", required=True, help="Standards directory")
@click.option("--magalix-account", "-a", required=True, default=MAGALIX_ACCOUNT, help="Magalix account ID")
@click.option("--policies-service", "-s", required=True, default=POLICIES_SVC_URL, help="Policies Service url")
@click.option("--new-only", is_flag=True, default=False, help="Sync only new standards")
@click.option("--sync-deleted", is_flag=True, default=False, help="Sync deleted standards and controls")
def standards(standards_dir, magalix_account, policies_service, new_only, sync_deleted):
    """Sync standards and controls"""
    syncer = StandardSyncer(policies_service=policies_service, magalix_account=magalix_account, standards_dir=standards_dir)
    syncer.sync(new_only=new_only, sync_deleted=sync_deleted)

@sync.command()
@click.option("--categories-dir", "-d", required=True, help="Categories directory")
@click.option("--magalix-account", "-a", required=True, default=MAGALIX_ACCOUNT, help="Magalix account ID")
@click.option("--policies-service", "-s", required=True, default=POLICIES_SVC_URL, help="Policies Service url")
@click.option("--new-only", is_flag=True, default=False, help="Sync only new categories")
@click.option("--sync-deleted", is_flag=True, default=False, help="Sync deleted categories")
def categories(magalix_account, policies_service, new_only, sync_deleted, categories_dir):
    """Sync categories"""
    syncer = CategorySyncer(policies_service=policies_service, magalix_account=magalix_account, categories_dir=categories_dir)
    syncer.sync(new_only=new_only, sync_deleted=sync_deleted)

if __name__ == '__main__':
    sync()