import requests
import zipfile
import os
import shutil
import json
import xml.etree.ElementTree as ET
import re
from time import time
import networkx as nx

class CweAsvsMapper:
    def __init__( self, tmp_dir, use_cache=False ):
        self.tmp_dir = tmp_dir
        self.use_cache = use_cache

    def download_latest_cwe_db( self ):
        
        cwe_xml_filename = f"{self.tmp_dir}/cwe.xml"
            
        if self.use_cache:
            return cwe_xml_filename
        
        print( "Download latest CWE database..." )

        latest_cwe_zip = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

        # Download from mitre.org
        with open( f"{self.tmp_dir}/cwec_latest.xml.zip", 'wb' ) as f :
            req = requests.get( latest_cwe_zip, allow_redirects=True )
            f.write( req.content )
        
        #Unzip contents
        zip_xml_filename = ""
        with zipfile.ZipFile( f"{self.tmp_dir}/cwec_latest.xml.zip", 'r' ) as zipf:
            for f in zipf.namelist():
                if f.endswith( '.xml' ) :
                    zip_xml_filename = f
                    break
            zipf.extract( zip_xml_filename, path=self.tmp_dir )

        os.rename( f"{self.tmp_dir}/{zip_xml_filename}", cwe_xml_filename )

        print( "OK!" )

        return cwe_xml_filename

    def get_namespace( self, element ):
        m = re.match(r'\{.*\}', element.tag)
        return m.group(0) if m else ''

    # Create a Digraph from CWEs where edges are "ChildOf" relationships
    def construct_cwe_graph( self, xml_file ):
        tree = ET.parse( xml_file )
        root = tree.getroot()
        namespace = self.get_namespace( root )

        cwe_items = {}
        cwe_graph = nx.DiGraph()
    
        child_of_attr = { "prop": "Nature", "val": "ChildOf" }
        cwe_id_attr = "CWE_ID"
        # CWE Weaknesses
        for weakness in root.findall( f'{namespace}Weaknesses/{namespace}Weakness' ):
            cwe_id = weakness.attrib['ID']
            if cwe_id not in cwe_items.keys():
                cwe_items[ cwe_id ] = { "parent_cwes": [], "child_cwes": [] }
                cwe_graph.add_node( cwe_id )
            for rel_wkns in weakness.findall( f'{namespace}Related_Weaknesses/{namespace}Related_Weakness' ):
                if child_of_attr['prop'] in rel_wkns.attrib.keys() and rel_wkns.attrib[ child_of_attr['prop'] ] == child_of_attr['val']:
                    rel_cwe_id = rel_wkns.attrib[ cwe_id_attr ]
                    if rel_cwe_id not in cwe_items.keys():
                        cwe_items[ rel_cwe_id ] = { "parent_cwes": [], "child_cwes": [] }
                    cwe_graph.add_edge( cwe_id, rel_cwe_id )
                    cwe_items[ cwe_id ][ "parent_cwes" ].append( rel_cwe_id )
                    cwe_items[ rel_cwe_id ][ "child_cwes" ].append( cwe_id )

        # CWE Categories
        for category in root.findall( f'{namespace}Categories/{namespace}Category' ):
            cwe_id = category.attrib['ID']
            if cwe_id not in cwe_items.keys():
                cwe_items[ cwe_id ] = { "parent_cwes": [], "child_cwes": [] }
                cwe_graph.add_node( cwe_id )
            for rel_wkns in category.findall( f'{namespace}Relationships/{namespace}Has_Member' ):
                rel_cwe_id = rel_wkns.attrib[ cwe_id_attr ]
                if rel_cwe_id not in cwe_items.keys():
                    cwe_items[ rel_cwe_id ] = { "parent_cwes": [], "child_cwes": [] }
                cwe_items[ rel_cwe_id ][ "parent_cwes" ].append( cwe_id )
                cwe_items[ cwe_id ][ "child_cwes" ].append( rel_cwe_id )
                cwe_graph.add_edge( cwe_id, rel_cwe_id )

        # CWE View
        for view in root.findall( f'{namespace}Views/{namespace}View' ):
            cwe_id = view.attrib['ID']
            if cwe_id not in cwe_items.keys():
                cwe_items[ cwe_id ] = { "parent_cwes": [], "child_cwes": [] }
                cwe_graph.add_node( cwe_id )
            for rel_wkns in view.findall( f'{namespace}Members/{namespace}Member' ):
                rel_cwe_id = rel_wkns.attrib[ cwe_id_attr ]
                if rel_cwe_id not in cwe_items.keys():
                    cwe_items[ cwe_id ] = { "parent_cwes": [], "child_cwes": [] }
                cwe_items[ cwe_id ][ "parent_cwes" ].append( cwe_id )
                cwe_items[ cwe_id ][ "child_cwes" ].append( cwe_id )

        return (cwe_graph, cwe_items)

    def download_latest_asvs_db( self ):

        json_filename = f"{self.tmp_dir}/asvs.json"

        if self.use_cache:
            return json_filename

        print( "Download latest ASVS database..." )
        
        asvs_v403_json = "https://github.com/OWASP/ASVS/releases/download/v4.0.3_release/OWASP.Application.Security.Verification.Standard.4.0.3-en.flat.json"
        latest_asvs_json = asvs_v403_json
        
        with open( json_filename, 'wb' ) as f:
            req = requests.get( latest_asvs_json )
            f.write( req.content )

        print( "OK!" )

        return json_filename

    def add_cwes_to_asvs( self, json_file, cwe_items, cwe_graph ):
        
        asvs_items = {}
        with open( json_file, 'r' ) as f:
            asvs_items = json.loads( f.read() )
        
        asvs_items['cwe_map'] = {}

        asvs_items['cwe_relationships'] = cwe_items

        for item in asvs_items['requirements'] :
            if not item["CWE"]:
                continue
            item["CWE_parents"] = list(set(self.get_cwe_ancestors( [item["CWE"]], cwe_items, "parent_cwes" )))
            item["CWE_children"] = list(set(self.get_cwe_ancestors( [item["CWE"]], cwe_items, "child_cwes" )))
            item["CWE_parents"].remove( item["CWE"] )
            item["CWE_children"].remove( item["CWE"] )
            item["CWE_related"] = item["CWE_parents"] + item["CWE_children"]
            asvs_items['cwe_map'][ item["CWE"] ] = asvs_items['cwe_map'].get(item["CWE"], []) +  [item["Item"][1:]]

        # Add ASVS of nearest mapped parents to CWE without ASVS mapping
        for cwe in sorted(cwe_graph.nodes, key=lambda node: cwe_graph.out_degree(node), reverse=True):
            if cwe in asvs_items['cwe_map'].keys():
                continue
            for edges in nx.edge_bfs(cwe_graph, cwe, orientation="reverse"):
                if edges[0] in asvs_items['cwe_map'].keys():
                    asvs_items['cwe_map'][cwe] = asvs_items['cwe_map'].get(cwe, []) + asvs_items['cwe_map'][edges[0]]
                    break

        return asvs_items

    def get_cwe_ancestors( self, asvs_cwes, cwe_source_list, key ):

        current_cwe = asvs_cwes[-1]

        if len( cwe_source_list[ current_cwe ][ key ] ) == 0:
            return asvs_cwes
        
        for parent_cwe in cwe_source_list[ current_cwe ][ key ] :
            asvs_cwes.append( parent_cwe )
            self.get_cwe_ancestors( asvs_cwes, cwe_source_list, key )
        
        return asvs_cwes


    def clear_workspace(self, ):
        shutil.rmtree( self.tmp_dir )

    def perform_mapping( self ):

        cwe_xml_filename = self.download_latest_cwe_db()
        asvs_json_filename = self.download_latest_asvs_db()

        print( "Normalizing data for lookups" )
        (cwe_graph, cwe_items) = self.construct_cwe_graph( cwe_xml_filename )
        asvs_items = self.add_cwes_to_asvs( asvs_json_filename, cwe_items, cwe_graph )
        return asvs_items
