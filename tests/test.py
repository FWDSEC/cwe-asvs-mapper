import json
import os
import glob

def main():
    scan_resultant_cwes = []
    with open( "./tests/test-cwes.json", "r" ) as f:
        scan_resultant_cwes = json.loads( f.read() )

    asvs_cwe_map = {}

    files = list(filter( os.path.isfile, glob.glob( "./out/*" ) ))
    files.sort( key=lambda x: os.path.getmtime(x) )
    with open( files[-1], 'r' ) as f:
        asvs_cwe_map = json.loads( f.read() )


    missing = 0
    for finding_cwe in scan_resultant_cwes:
        
        # trim off "CWE-"
        finding_cwe = finding_cwe[0][4:]

        # If there's no direct match look through CWEs parents
        if finding_cwe not in asvs_cwe_map['cwe_map'].keys():

            if finding_cwe not in asvs_cwe_map['cwe_relationships']:
                print( f"CWE ID \"{finding_cwe}\" is malformed" )
                continue

            for cwe_rel in asvs_cwe_map['cwe_relationships'][finding_cwe]['parent_cwes']:
                if cwe_rel not in asvs_cwe_map['cwe_map'].keys():
                    missing += 1
                else:
                    asvs_items_found = ",".join( asvs_cwe_map['cwe_map'][cwe_rel] )
                    print( f"{finding_cwe} -> [{asvs_items_found}]" )
        else:
            asvs_items_found = ",".join( asvs_cwe_map['cwe_map'][finding_cwe] )
            print( f"{finding_cwe} -> [{asvs_items_found}]" )
        
    if not missing:
        print( "OK! Finished without a missed finding." )

    return missing

main()