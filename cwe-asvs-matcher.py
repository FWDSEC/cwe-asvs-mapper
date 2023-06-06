import requests
import zipfile
import os
import shutil
import json
import xml.etree.ElementTree as ET
import re
from time import time


tmp_dir = "./tmp"

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

def download_latest_cwe_db( use_cache = False ):
    
    cwe_xml_filename = f"{tmp_dir}/cwe.xml"
        
    if use_cache:
        return cwe_xml_filename
    
    print( "Download latest CWE database..." )

    latest_cwe_zip = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

    # Download from mitre.org
    with open( f"{tmp_dir}/cwec_latest.xml.zip", 'wb' ) as f :
        req = requests.get( latest_cwe_zip, allow_redirects=True )
        f.write( req.content )
    
    #Unzip contents
    zip_xml_filename = ""
    with zipfile.ZipFile( f"{tmp_dir}/cwec_latest.xml.zip", 'r' ) as zipf:
        for f in zipf.namelist():
            if f.endswith( '.xml' ) :
                zip_xml_filename = f
                break
        zipf.extract( zip_xml_filename, path=tmp_dir )

    os.rename( f"{tmp_dir}/{zip_xml_filename}", cwe_xml_filename )

    print( "OK!" )

    return cwe_xml_filename

def get_namespace( element ):
    m = re.match(r'\{.*\}', element.tag)
    return m.group(0) if m else ''

def normalize_cwe( xml_file ):
  
    tree = ET.parse( xml_file )
    root = tree.getroot()
    namespace = get_namespace( root )

    cwe_items = {}
  
    child_of_attr = { "prop": "Nature", "val": "ChildOf" }
    cwe_id_attr = "CWE_ID"
    # CWE Weaknesses
    for weakness in root.findall( f'{namespace}Weaknesses/{namespace}Weakness' ):
  
        if weakness.attrib['ID'] not in cwe_items.keys():
            cwe_items[ weakness.attrib['ID'] ] = { "parent_cwes": [], "child_cwes": [] }

        for rel_wkns in weakness.findall( f'{namespace}Related_Weaknesses/{namespace}Related_Weakness' ):

            if child_of_attr['prop'] in rel_wkns.attrib.keys() and rel_wkns.attrib[ child_of_attr['prop'] ] == child_of_attr['val']:
                if rel_wkns.attrib[ cwe_id_attr ] not in cwe_items.keys():
                    cwe_items[ rel_wkns.attrib[ cwe_id_attr ] ] = { "parent_cwes": [], "child_cwes": [] }
                cwe_items[ weakness.attrib['ID'] ][ "parent_cwes" ].append( rel_wkns.attrib[ cwe_id_attr ] )
                cwe_items[ rel_wkns.attrib[ cwe_id_attr ] ][ "child_cwes" ].append( weakness.attrib['ID'] )
    
    # CWE Categories
    for category in root.findall( f'{namespace}Categories/{namespace}Category' ):
  
        if category.attrib['ID'] not in cwe_items.keys():
            cwe_items[ category.attrib['ID'] ] = { "parent_cwes": [], "child_cwes": [] }

        for rel_wkns in category.findall( f'{namespace}Relationships/{namespace}Has_Member' ):

            if rel_wkns.attrib[ cwe_id_attr ] not in cwe_items.keys():
                cwe_items[ rel_wkns.attrib[ cwe_id_attr ] ] = { "parent_cwes": [], "child_cwes": [] }
            cwe_items[ rel_wkns.attrib[ cwe_id_attr ] ][ "parent_cwes" ].append( category.attrib['ID'] )
            cwe_items[ category.attrib['ID'] ][ "child_cwes" ].append( rel_wkns.attrib[ cwe_id_attr ] )
    
    # CWE View
    for view in root.findall( f'{namespace}Views/{namespace}View' ):
  
        if view.attrib['ID'] not in cwe_items.keys():
            cwe_items[ view.attrib['ID'] ] = { "parent_cwes": [], "child_cwes": [] }

        for rel_wkns in view.findall( f'{namespace}Members/{namespace}Member' ):

            if rel_wkns.attrib[ cwe_id_attr ] not in cwe_items.keys():
                cwe_items[ rel_wkns.attrib[ cwe_id_attr ] ] = { "parent_cwes": [], "child_cwes": [] }
            cwe_items[ rel_wkns.attrib[ cwe_id_attr ] ][ "parent_cwes" ].append( view.attrib['ID'] )
            cwe_items[ view.attrib['ID'] ][ "child_cwes" ].append( rel_wkns.attrib[ cwe_id_attr ] )
      
    return cwe_items

def download_latest_asvs_db( use_cache ):

    json_filename = f"{tmp_dir}/asvs.json"

    if use_cache:
        return json_filename

    print( "Download latest ASVS database..." )
    
    asvs_v403_json = "https://github.com/OWASP/ASVS/releases/download/v4.0.3_release/OWASP.Application.Security.Verification.Standard.4.0.3-en.flat.json"
    latest_asvs_json = asvs_v403_json
    
    with open( json_filename, 'wb' ) as f:
        req = requests.get( latest_asvs_json )
        f.write( req.content )

    print( "OK!" )

    return json_filename

def add_cwes_to_asvs( json_file, cwe_items ):
    
    asvs_items = {}
    with open( json_file, 'r' ) as f:
        asvs_items = json.loads( f.read() )
    
    asvs_items['cwe_map'] = {}

    asvs_items['cwe_relationships'] = cwe_items

    for item in asvs_items['requirements'] :
        if not item["CWE"]:
            continue

        item["CWE_parents"] = list(set(get_cwe_ancestors( [item["CWE"]], cwe_items, "parent_cwes" )))
        item["CWE_children"] = list(set(get_cwe_ancestors( [item["CWE"]], cwe_items, "child_cwes" )))
        item["CWE_parents"].remove( item["CWE"] )
        item["CWE_children"].remove( item["CWE"] )
        item["CWE_related"] = item["CWE_parents"] + item["CWE_children"]

        # Add inverted list
        for cwe in item["CWE_related"]:
            if cwe not in asvs_items['cwe_map'].keys():
                asvs_items['cwe_map'][ cwe ] = []
            asvs_items['cwe_map'][ cwe ].append( item["Item"][1:] )

    return asvs_items

def get_cwe_ancestors( asvs_cwes, cwe_source_list, key ):

    current_cwe = asvs_cwes[-1]

    if len( cwe_source_list[ current_cwe ][ key ] ) == 0:
        return asvs_cwes
    
    for parent_cwe in cwe_source_list[ current_cwe ][ key ] :
        asvs_cwes.append( parent_cwe )
        get_cwe_ancestors( asvs_cwes, cwe_source_list, key )
    
    return asvs_cwes


def clear_workspace():
    shutil.rmtree( tmp_dir )

def main():

    use_cache = init_workspace()

    cwe_xml_filename = download_latest_cwe_db( use_cache )
    asvs_json_filename = download_latest_asvs_db( use_cache )

    print( "Normalizing data for lookups" )
    cwe_items = normalize_cwe( cwe_xml_filename )
    asvs_items = add_cwes_to_asvs( asvs_json_filename, cwe_items )

    output_dir = "./out"
    if not os.path.exists( output_dir ):
        os.mkdir( output_dir )
    output_file = f'{output_dir}/asvs-w-all-cwes.{int(time())}.json'
    with open( output_file, 'w' ) as f:
        f.write( json.dumps( asvs_items, indent=4 ) )

    #clear_workspace()

    print( "Complete!" )
    print( f"File written to {output_file}" )


main()