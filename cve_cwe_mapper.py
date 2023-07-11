import json
import re
import os
import requests
from zipfile import ZipFile

class CweCveMapper:
    def __init__( self, tmp_dir, use_cache = False ):
        self.tmp_dir = tmp_dir
        self.use_cache = use_cache

    def download_latest_cve_db( self ):

        cve_directory_name = f"{self.tmp_dir}/cve_latest"

        if self.use_cache:
            return cve_directory_name
        
        print( "Download latest CVE database..." )

        releases_response = requests.get("https://api.github.com/repos/CVEProject/cvelistV5/releases/latest")
        releases_json = json.loads(releases_response.content)
        assets = releases_json.get("assets", [])
        cve_assets = [asset for asset in assets if re.match(r'.*_all_CVEs_at_midnight.zip.zip', asset.get("name", ""))]
        if len(cve_assets) > 0:
            cve_asset = cve_assets[0]
            cve_asset_url = cve_asset.get("browser_download_url")
            cve_asset_name = cve_asset.get("name")
            cve_asset_zip_path = f"{self.tmp_dir}/{cve_asset_name}"
            with open(cve_asset_zip_path, 'wb') as f:
                req = requests.get(cve_asset_url, allow_redirects=True)
                f.write(req.content)
            print( "OK!" )
            print( "Unzip latest CVE database..." )
            ZipFile(cve_asset_zip_path).extractall(cve_directory_name)
            ZipFile(f"{cve_directory_name}/cves.zip").extractall(f"{cve_directory_name}/cves")
            os.remove(cve_asset_zip_path)
            print( "OK! ")
            return cve_directory_name

    def cve_has_cwe( self, cve ):
        problems = cve.get("containers").get("cna").get("problemTypes", [])
        for problem in problems:
            for description in problem.get("descriptions", []):
                if description.get("type") == "CWE":
                    return True
                
    def cve_generator( self, cve_directory_name ):
        for root, _, files in os.walk(f"{cve_directory_name}/cves/cves"):
            for file in files:
                if (re.match(r"CVE-.*\.json", file) == None):
                    continue
                with open(f"{root}/{file}") as f:
                    cve_json = json.load(f)
                    if self.cve_has_cwe(cve_json):
                        yield cve_json

    def map_cve_to_cwe( self, cve_directory_name ):
        cve_to_cwe = {}
        for item in self.cve_generator(cve_directory_name):
            cwes = []
            for problem in item.get("containers").get("cna").get("problemTypes", []):
                for description in problem.get("descriptions", []):
                    if description.get("type") == "CWE":
                        if description.get("value") == "NVD-CWE-noinfo":
                            continue
                        cwes.append(description.get("cweId"))
            cve_to_cwe[item.get("cveMetadata").get("cveId")] = cwes
        return cve_to_cwe

    def perform_mapping( self ):
        cve_directory_name = self.download_latest_cve_db()
        cve_to_cwe = self.map_cve_to_cwe(cve_directory_name)
        return cve_to_cwe