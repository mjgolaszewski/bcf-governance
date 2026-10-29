"""UNRUN read-only canonical policy probe, only inside Root-admitted app exec.

Native ExecID completion + independently bound container/config/source attestation
are required outside this JSON. No settings or secret values are serialized.
"""
import hashlib
import json
from pathlib import Path
import sys


def main():
    if len(sys.argv)!=2 or not 1<=len(sys.argv[1])<=128:
        raise RuntimeError('exact canonical operation required')
    operation=sys.argv[1]
    from chrysalis_identity import config_catalog
    from chrysalis_identity.api import admin_context_policy
    from chrysalis_identity.settings import get_settings
    settings=get_settings()
    path=config_catalog.configured_catalog_path()
    if path is None:
        raise RuntimeError('explicit actual runtime catalog required')
    source=Path(admin_context_policy.__file__)
    result={'source_origin':str(source),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'configuration_origin':str(path),'configuration_sha256':config_catalog.catalog_file_fingerprint(path),
        'profile':config_catalog.configured_catalog_profile(),'operation':operation,
        'requires_approval':admin_context_policy._approval_required(settings,operation_name=operation),
        'requires_strong_auth':settings.admin_require_strong_auth_for_admin_access,
        'requires_step_up':settings.admin_require_step_up_for_dangerous_mutations}
    print(json.dumps(result,allow_nan=False))

if __name__=='__main__':main()
