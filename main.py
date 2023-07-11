import shutil, os, json
from cve_cwe_mapper import CweCveMapper
from cwe_asvs_mapper import CweAsvsMapper
from time import time

rel_dir = "/shared" if os.environ.get('INSIDE_DOCKER', "") else "."
tmp_dir = f"{rel_dir}/tmp"

def init_workspace():

    use_cache = False
    if os.path.exists( tmp_dir ):

        if int( time() ) - int( os.path.getmtime( tmp_dir ) ) < 86000:
            print( "DBs less than 1 day old. Using cache." )
            use_cache = True
            return use_cache

        # Clear and create working dir
        shutil.rmtree( tmp_dir )

    os.mkdir( tmp_dir )

    return use_cache

def main():
    use_cache = init_workspace()
    cve_to_cwe_mapper = CweCveMapper( tmp_dir, use_cache )
    cwe_to_asvs_mapper = CweAsvsMapper( tmp_dir, use_cache )
    
    output_dir = f"{rel_dir}/out"
    if not os.path.exists( output_dir ):
        os.mkdir( output_dir )
    cve_to_cwe_output_file = f'{output_dir}/cve-to-cwe.{int(time())}.json'
    cwe_to_asvs_output_file = f'{output_dir}/cwe-to-asvs.{int(time())}.json'
    with open( cve_to_cwe_output_file, 'w' ) as f:
        json.dump( cve_to_cwe_mapper.perform_mapping(), f)
    with open( cwe_to_asvs_output_file, 'w' ) as f:
        json.dump( cwe_to_asvs_mapper.perform_mapping(), f)
main()