#author: Nicolas Ranc @pathtaga

from R2Log import logger
from rich.console import Console
from rich.table import Table

from lxml.builder import unicode
from pycvss.pycvss import *     # pip install pycvss
from cvss import CVSS3          # pip install cvss

import json
from docxtpl import DocxTemplate

import argparse
import sys
import os
import re
import glob
from packaging.version import parse
from deep_translator import GoogleTranslator

import html

import json
import sys
import xml.etree.cElementTree as ElementTree

import fsb_reco


VERSION = "1.0.0"

banner = """Dependency check & FindSec bugs parser %s - From [Jar/war] & [src code] to Docx\n\n Fill ./apps/ repository with :\n\t- Binary files (war,jar,zip,ear, ...) inside ./apps/<package_name>/bin/ \n\t- Source code inside ./apps/<package_name>/src/>\n""" % VERSION

numvulnid = 0
numpackage = 0

dpcheck_extensions = [".zip",".ear",".war",".jar",".sar",".apk",".nupkg",".tar",".gz",".tgz",".bz2",".tbz2",".rpm",".exe",".dll",".js","package.json",".nupsec","opensslv.h","configure","configure.in","configure.ac","CMakeLists.txt",".cmake",".podspec","composer.lock",".py",".whl",".egg",".gemspec"]
fsb_extensions = [".jar",".war",".zip",".ear"]

def parseArgs():
    print(banner)
    parser = argparse.ArgumentParser(description="A python script to do your report.")

    group_checker = parser.add_argument_group("Dependency Checker plugin")
    group_checker.add_argument("--no-dep-check", default=None, type=str, help="Disable Dependency Check plugin. [Default : False]")

    group_findbugs = parser.add_argument_group("Find Sec Bugs plugin")
    group_findbugs.add_argument("--no-findsecbugs", default=None, type=str, help="Disable FindSecBugs plugin. [Default : False]")

    group_findbugs = parser.add_argument_group("Export")
    group_findbugs.add_argument("--export-docx", dest="export_docx", type=str, default=None, required=False,
                              help="Output DOCX file to store the results in.")

    group_config = parser.add_argument_group("Configuration")
    group_config.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (-v for verbose, -vv for advanced, -vvv for debug)")

    args = parser.parse_args()

    if args.no_dep_check:
        logger.info("Dependency Check plugin disable.")
    if args.no_findsecbugs:
        logger.info("FindSecBugs plugin disable.")
    if args.export_docx is None:
        logger.warning("No DOCX specified.")
        sys.exit(1)
    return args

def translate(sentence):
    translate = GoogleTranslator(source='auto', target='fr').translate(sentence)
    if translate is not None :
        logger.advanced(translate)
        translate = translate.replace("<x:","")
        translate = translate.replace(">", "")
        translate = translate.replace("<", "")
        return translate
    else:
        logger.error("Error translate.")
        logger.advanced(translate)
        sentence = sentence.replace("<x:", "")
        sentence = sentence.replace("<", "")
        sentence = sentence.replace(">", "")
        return sentence

def extract_highest_version(text):
    regex = '((([0-9]+)\.([0-9]+))(\.([0-9]+))?(-([0-9a-zA-Z.-]+))?)'
    matched = re.findall(regex, text)
    highestVersion = "-1"
    if matched is not None:
        for version in [result[0] for result in matched]:
            try:
                if parse(version) > parse(highestVersion):
                    highestVersion = version
                else:
                    pass
            except Exception as e:
                logger.error(e)
                return None
        return highestVersion
    else:
        return None

def get_important_vulns(data, scan_id, appName=None):
    if appName is not None:
        logger.info("Parsing "+appName+" JSON...")
    else:
        logger.info("Parsing JSON...")

    global numvulnid
    global numpackage

    global nb_cve_2015
    global nb_cve_2016
    global nb_cve_2017
    global nb_cve_2018
    global nb_cve_2019
    global nb_cve_2020
    global nb_cve_2021
    global nb_cve_2022

    """
    tmp_nb_cve_2015 = 0
    tmp_nb_cve_2016 = 0
    tmp_nb_cve_2017 = 0
    tmp_nb_cve_2018 = 0 
    tmp_nb_cve_2019 = 0
    tmp_nb_cve_2020 = 0
    tmp_nb_cve_2021 = 0
    tmp_nb_cve_2022 = 0
    """

    minCVSS = 7
    logger.advanced("minCVSS :"+str(minCVSS))

    try:
        data = json.loads(data)
    except Exception as e:
        logger.error(e)
        sys.exit(1)
    module_results = []
    vuln_status = ''
    vuln_bg = ''
    reco_status = ''
    reco_bg = ''
    highestVersion = "-1"
    currentPackageVersion = "10000"
    namePackage = ''
    # skip #1 as it's the package itself
    for dependency in data['dependencies'][1:]:
        numpackage = numpackage +1
        vuln_status = ''
        vuln_bg = ''
        reco_status = ''
        reco_bg = ''
        titlereco = ''
        highestVersion = "-1"

        try:
            namePackage = dependency['fileName'].split(' ', 1)[1]
        except:
            namePackage = dependency['fileName']

        logger.advanced("Nom du packet : "+namePackage)

        currentPackageVersion = extract_highest_version(namePackage)

        if appName is not None:
            fileName = appName + " - Dépendance "+namePackage+" obsolète"
            titlereco = appName +" - Mettre à jour le paquet "+namePackage
        else:
            fileName = "Dépendance " + namePackage + " obsolète"
            titlereco = "Mettre à jour le paquet " + namePackage

        vulnList = []
        reference = []
        linkCVSSv3 = []
        vulnToPost = False
        # if package contains vulnerabilities

        if 'vulnerabilities' in dependency:
            if 'packages' in dependency:
                # retrieve packages with confidence HIGH & HIGHEST
                packages = [p for p in dependency['packages']
                            if p['confidence'] == 'HIGH' or p['confidence'] == 'HIGHEST']
                # package known
                if len(packages) > 0:
                    highestScoreCVSSv2 = -1
                    highestScoreCVSSv3 = -1
                    max_vuln = 0
                    for vulnerability in dependency['vulnerabilities']:
                        vulnContent = ''
                        year = "9999"
                        try:
                            name = vulnerability['name']
                            year = name.split("-")[1]
                        except:
                            name = None

                        try:
                            description = translate(vulnerability['description'])
                        except:
                            description = vulnerability['description']

                        currentVersion = extract_highest_version(description)
                        if currentVersion is not None:
                            if parse(currentVersion) > parse(highestVersion):
                                highestVersion = currentVersion

                        scoreCVSSv2 = -1
                        impactCVSSv2 = -1
                        exploitabilityCVSSv2 = -1
                        stringCVSSv2 = ""

                        if 'cvssv2' in vulnerability:
                            # if 'score' in vulnerability['cvssv2']:
                            scoreCVSSv2 = vulnerability['cvssv2']['score']
                            severityCVSSv2 = vulnerability['cvssv2']['severity']

                        scoreCVSSv3 = -1
                        impactCVSSv3 = -1
                        exploitabilityCVSSv3 = -1
                        stringCVSSv3 = ""
                        if 'cvssv3' in vulnerability:
                            scoreCVSSv3 = vulnerability['cvssv3']['baseScore']
                            severityCVSSv3 = vulnerability['cvssv3']['baseSeverity']

                        # vulnerability with scoreCVSSv2 or scoreCVSSv3 >= 7
                        if scoreCVSSv2 >= minCVSS or scoreCVSSv3 >= minCVSS:
                            vulnToPost = True

                            vulnContent += name
                            reference.append(name + " ")
                            if scoreCVSSv2 != -1:
                                vulnContent += ' | CVSSv2: ' + \
                                    str(scoreCVSSv2) + \
                                    ' (' + severityCVSSv2 + ')'
                                if scoreCVSSv2 > highestScoreCVSSv2:
                                    highestScoreCVSSv2 = scoreCVSSv2
                                    if "$" == vulnerability['cvssv2']['authenticationr'][:1]:
                                        vulnerability['cvssv2']['authenticationr'] = 'N'
                                    stringCVSSv2 = "AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s" % (
                                        vulnerability['cvssv2']['accessVector'][:1],
                                        vulnerability['cvssv2']['accessComplexity'][:1],
                                        vulnerability['cvssv2']['authenticationr'][:1],
                                        vulnerability['cvssv2']['confidentialImpact'][:1],
                                        vulnerability['cvssv2']['integrityImpact'][:1],
                                        vulnerability['cvssv2']['availabilityImpact'][:1]
                                    )
                                    try:
                                        c = Cvss.from_vector(stringCVSSv2)
                                        impactCVSSv2 = round(c.impact, 2)
                                        exploitabilityCVSSv2 = round(c.base_exploitability, 2)
                                    except Exception as e:
                                        logger.warning(e)

                            if scoreCVSSv3 != -1:
                                vulnContent += ' | CVSSv3: ' + \
                                    str(scoreCVSSv3) + \
                                    ' (' + severityCVSSv3 + ')'
                                if scoreCVSSv3 > highestScoreCVSSv3:
                                    highestScoreCVSSv3 = scoreCVSSv3
                                    stringCVSSv3 = "CVSS:3.0/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s" % (
                                        vulnerability['cvssv3']['attackVector'][:1],
                                        vulnerability['cvssv3']['attackComplexity'][:1],
                                        vulnerability['cvssv3']['privilegesRequired'][:1],
                                        vulnerability['cvssv3']['userInteraction'][:1],
                                        vulnerability['cvssv3']['scope'][:1],
                                        vulnerability['cvssv3']['confidentialityImpact'][:1],
                                        vulnerability['cvssv3']['integrityImpact'][:1],
                                        vulnerability['cvssv3']['availabilityImpact'][:1]
                                    )
                                    try:
                                        c = CVSS3(stringCVSSv3)
                                        impactCVSSv3 = round(c.isc, 2)
                                        exploitabilityCVSSv3 = round(c.esc, 2)
                                        linkCVSSv3.append("https://www.first.org/cvss/calculator/3.0#" + stringCVSSv3)
                                    except Exception as e:
                                        logger.warning(e)
                            vulnContent += '\n'
                            vulnContent += description
                            vulnList.append(vulnContent)

                    if highestVersion != "-1":
                        if parse(currentPackageVersion) > parse(highestVersion):
                            if appName is not None:
                                logger.warning("Dependency Check made a mistake : application :"+appName+" - package "+namePackage+" which is version "+currentPackageVersion+" isn't vulnerable to CVEs (vulnerable version <"+highestVersion+").")
                            else:
                                logger.warning("Dependency Check made a mistake : package "+namePackage+" which is version "+currentPackageVersion+" isn't vulnerable to CVEs (vulnerable version <"+highestVersion+").")
                            logger.warning(namePackage+" is removed.")
                            continue

                    if vulnToPost:
                        for cve in reference:
                            if cve.split("-")[1] == "2015":
                                nb_cve_2015 += 1
                            elif cve.split("-")[1] == "2016":
                                nb_cve_2016 += 1
                            elif cve.split("-")[1] == "2017":
                                nb_cve_2017 += 1
                            elif cve.split("-")[1] == "2018":
                                nb_cve_2018 += 1
                            elif cve.split("-")[1] == "2019":
                                nb_cve_2019 += 1
                            elif cve.split("-")[1] == "2020":
                                nb_cve_2020 += 1
                            elif cve.split("-")[1] == "2021":
                                nb_cve_2021 += 1
                            elif cve.split("-")[1] == "2022":
                                nb_cve_2022 += 1

                        # scoreCVSSv2 > scoreCVSSv3
                        if highestScoreCVSSv2 > highestScoreCVSSv3:
                            if impactCVSSv2 == 0:
                                impact_id = 1  # Faible (42) / Très faible (JIRA)
                            elif impactCVSSv2 > 0 and impactCVSSv2 < 4:
                                impact_id = 2  # Modéré (42) / Faible (JIRA)
                            elif impactCVSSv2 >= 4 and impactCVSSv2 < 7:
                                impact_id = 3  # Important (42) / Moyen (JIRA)
                            else:
                                impact_id = 4  # Critique (42) / Fort (JIRA)

                            if exploitabilityCVSSv2 == 0:
                                complexity_id = 1  # Facile (42/JIRA)
                            elif exploitabilityCVSSv2 > 0 and exploitabilityCVSSv2 < 4:
                                complexity_id = 2  # Modérée (42/JIRA)
                            elif exploitabilityCVSSv2 >= 4 and exploitabilityCVSSv2 < 7:
                                complexity_id = 3 # Elevée (42/JIRA)
                            else:
                                complexity_id = 4  # Difficile (42/JIRA)
                        # scoreCVSSv3 > scoreCVSSv2
                        else:
                            if impactCVSSv3 == 0:
                                impact_id = 1  # Faible (42) / Très faible (JIRA)
                            elif impactCVSSv3 > 0 and impactCVSSv3 < 4:
                                impact_id = 2  # Modéré (42) / Faible (JIRA)
                            elif impactCVSSv3 >= 4 and impactCVSSv3 < 7:
                                impact_id = 3  # Important (42) / Moyen (JIRA)
                            else:
                                impact_id = 4  # Critique (42) / Fort (JIRA)

                            if exploitabilityCVSSv3 == 0:
                                complexity_id = 1  # Facile (42/JIRA)
                            elif exploitabilityCVSSv2 > 0 and exploitabilityCVSSv2 < 4:
                                complexity_id = 2  # Modérée (42/JIRA)
                            elif exploitabilityCVSSv3 >= 4 and exploitabilityCVSSv3 < 7:
                                complexity_id = 3  # Elevée (42/JIRA)
                            else:
                                complexity_id = 4  # Difficile (42/JIRA)

                        if highestScoreCVSSv2 >= 9 or highestScoreCVSSv3 >= 9:
                            """
                            risk_id = 5  # Bloquant
                            vuln_status = "Bloquant"
                            vuln_bg = "#8B0000"
                            reco_status = "Haute"
                            reco_bg = "#8B0000"
                            """
                            risk_id = 4  # Critique
                            vuln_status = "Critique"
                            vuln_bg = "#FF8C00"
                            reco_status = "Haute"
                            reco_bg = "#8B0000"

                        elif highestScoreCVSSv2 >= 8 or highestScoreCVSSv3 >= 8:
                            risk_id = 4  # Critique
                            vuln_status = "Critique"
                            vuln_bg = "#FF8C00"
                            reco_status = "Haute"
                            reco_bg = "#8B0000"
                        else:
                            risk_id = 3  # Majeur
                            vuln_status = "Majeur"
                            vuln_bg = "Orange"
                            reco_status = "Moyenne"
                            reco_bg = "#FF8C00"

                        if highestVersion == "-1":
                            descriptionreco = "Mettre à jour le paquet afin qu'il ne soit plus vulnérable aux CVEs mentionnées ci-dessus."
                        else:
                            descriptionreco = "Mettre à jour le paquet avec une version >"+highestVersion+"."

                        numvulnid = numvulnid + 1

                        module_result = {
                            "scan_id": scan_id,
                            "appname": appName,
                            "module_name": "AjoutManuelDeVuln",
                            "result": True,
                            "output": {
                                "module_result": {
                                    "numvulnid" : numvulnid,
                                    "module": "AjoutManuelDeVuln",
                                    "version": "0.1",
                                    "titlevuln": fileName,
                                    "description": '\n\n'.join(vulnList),
                                    "reference" : "".join(reference),
                                    "impact": "Fort",
                                    "difficult": "Moyenne",
                                    "cvsslink":'\n'.join(linkCVSSv3),
                                    "result": "La vulnérabilité est avérée.",
                                    "titlereco": titlereco,
                                    "descriptionreco": descriptionreco,
                                    "responsable": "Equipe de développement"

                                }
                            },
                            "vulnerability_code": "DEP_OBS_",
                            "risk_id": risk_id,
                            "impact_id": impact_id,
                            "vuln_status":vuln_status,
                            "vuln_bg":vuln_bg,
                            "reco_status":reco_status,
                            "reco_bg":reco_bg,
                            "complexity_id": complexity_id
                        }
                        logger.advanced(module_result)
                        module_results.append(module_result)
    logger.success("Found " + str(len(module_results)) + " vulnerabilities.")
    return module_results

def display_export_synthese(name, synthese):
    logger.info("Displaying synthese for report...")
    table = Table(title="Synthese for report")

    table.add_column("Name", justify="right", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    for i in synthese:
        table.add_row(i, str(synthese[i]))

    console = Console(record=True)
    console.print(table)

    # Get console output as text
    synthesePath = ".\\results\\synthese_{}.txt".format(name)
    text = console.export_text()
    with open(synthesePath, "w", encoding="utf-8") as file:
        file.write(text)
    logger.info("Synthese saved at location : "+synthesePath)

def create_docx_multiple_jsons(vulns,name, synthese):
    logger.info("Creating Docx...")
    #tpl = DocxTemplate('templates/RVS_template_DD_TI_several.docx')
    tpl = DocxTemplate('templates/template_word.docx')
    test = []
    for vuln in vulns:
        test.append(vuln)
        break
    try:
        #tpl.render(context={"vulnss":vulns})
        tpl.render(context={"vulnss":vulns,"synthese":synthese})
    except Exception as e:
        logger.error(e)
        sys.exit(1)

    filename = unicode("results/"+name+".docx")
    tpl.save(filename)
    logger.success("Docx successfully created at "+filename)

def from_archive_to_jsons(rootPackagePath):
    #Extract .jar and .war to JSON
    #Please extract .dar before

    commande = ""
    dpcheck_bin_path = ""
    name_arch = ""
    jsonPath = ""
    nb_jar_file = 0

    prefix = " -s "
    alldepcheckfiles = ""
    logger.info("Converting archive files from package "+rootPackagePath.split("\\")[-1]+" into JSONs ")
    if os.name == "nt":
        for archivePath in glob.iglob(rootPackagePath+"\\bin\\**", recursive=True):
            dpcheck_bin_path = ".\\tools\\dependency-check\\bin\\dependency-check.bat"
            name_arch = archivePath.split("\\")[-1]

            for extension in dpcheck_extensions:
                if extension == ".zip" and ".zip" in name_arch:
                    alldepcheckfiles = alldepcheckfiles + prefix + archivePath
                    nb_jar_file = nb_jar_file + 1
                elif extension in name_arch and ".zip" in archivePath:
                    pass
                elif extension in name_arch:
                    alldepcheckfiles = alldepcheckfiles + prefix + archivePath
                    nb_jar_file = nb_jar_file + 1

        logger.info("Found "+str(nb_jar_file)+" files to investigate.")
        logger.verbose("Dependency check files to analyze : "+alldepcheckfiles)

        commande = dpcheck_bin_path + " --format JSON -o "+archivePath.split("\\")[0]+"\\"+archivePath.split("\\")[1]+"\\"+archivePath.split("\\")[2]+"\\ "+alldepcheckfiles
        os.system(commande)
        logger.verbose("JSON file created.")
    else:
        logger.error("Please run me on windows")
        sys.exit(1)

def collection_jsons_from_packagepath(rootPackagePath):
    jsonFilesPaths = []
    for absolutePathFile in glob.iglob(rootPackagePath + "\\*", recursive=False):
        if "dependency-check-report.json" in absolutePathFile:
            logger.verbose("Add file:" + absolutePathFile)
            jsonFilesPaths.append(absolutePathFile)
    logger.success("Found " + str(len(jsonFilesPaths)) + " JSONs files.")
    if len(jsonFilesPaths) == 0:
        logger.error(
            "Something is wrong, 0 JSON selected.")
        return 0
    else:
        return jsonFilesPaths

def create_findsecbugs_xml(rootPackagePath):
    stringJarPaths = ""
    logger.info("Create XML from FindSecBugs plugin.")
    nb_jar_file = 0
    if os.name == "nt":
        #for sourcesCodePath in glob.iglob(rootPackagePath+"\\src\\**", recursive=True):
        sourcesCodePath = rootPackagePath+"\\src"
        findsecbugs_bin_path = ".\\tools\\find-sec-bugs\\cli\\findsecbugs.bat"
        name_arch = sourcesCodePath.split("\\")[2]

        for jarfile in glob.iglob(rootPackagePath+"\\bin\\**", recursive=True):
            jarname = jarfile.split("\\")[-1]
            for extension in fsb_extensions:
                if extension == ".zip" and ".zip" in jarname:
                    #problem with .zip , don't know why
                    #stringJarPaths = stringJarPaths + " " + jarfile
                    #nb_jar_file = nb_jar_file + 1
                    pass
                elif extension in jarname and ".zip" in jarfile:
                    pass
                elif extension in jarname:
                    stringJarPaths = stringJarPaths + " " + jarfile
                    nb_jar_file = nb_jar_file + 1

        logger.success("Found "+str(nb_jar_file)+" archive files")
        logger.verbose("FindSecBugs files to analyze : " + stringJarPaths)

        if nb_jar_file == 0:
            logger.warning("No coherent archive file found for "+rootPackagePath.split("\\")[-1]+". Please add bin inside /app/bin/ folder.")
            pass
        else:
            #command_fsb_low = findsecbugs_bin_path+' -quiet -progress -low -nested:false -xml:withMessages -sourcepath '+sourcesCodePath+" -output "+sourcesCodePath.split("\\")[0]+"\\"+sourcesCodePath.split("\\")[1]+"\\"+sourcesCodePath.split("\\")[2]+"\\findsecbugs_low.xml "+stringJarPaths
            command_fsb_medium = findsecbugs_bin_path+' -quiet -progress -medium -nested:false -xml:withMessages -sourcepath '+sourcesCodePath+" -output "+sourcesCodePath.split("\\")[0]+"\\"+sourcesCodePath.split("\\")[1]+"\\"+sourcesCodePath.split("\\")[2]+"\\findsecbugs_medium.xml "+stringJarPaths
            #command_fsb_high = findsecbugs_bin_path+' -quiet -progress -high -nested:false -xml:withMessages -sourcepath '+sourcesCodePath+" -output "+sourcesCodePath.split("\\")[0]+"\\"+sourcesCodePath.split("\\")[1]+"\\"+sourcesCodePath.split("\\")[2]+"\\findsecbugs_high.xml "+stringJarPaths
            #logger.info("Running FindSecBugs plugin [LOW] on "+name_arch)
            #os.system(command_fsb_low)
            logger.info("Running FindSecBugs plugin [MEDIUM] on " + name_arch)
            os.system(command_fsb_medium)
            #logger.info("Running FindSecBugs plugin [HIGH] on " + name_arch)
            #os.system(command_fsb_high)
            logger.info("End of FindSecBugs plugin on "+name_arch)
    else:
        logger.error("Please run me on windows")
        sys.exit(1)
    logger.verbose("End of converting archive files into JSONs ")

def parse_findsecbugs_results(rootPackagePath, appName=None):
    results = []

    global numvulnid

    logger.info("Parsing "+rootPackagePath.split("\\")[-1]+" FindSecBugs XMLs...")

    vuln_status = "Statut"
    vuln_bg = "hexval"
    reco_status = "Statut"
    reco_bg = "Background"

    title = ""
    impact = ""
    difficulty = ""

    vulns = []

    if os.name == "nt":
        for xmlPath in glob.iglob(rootPackagePath+"\\findsecbugs*.xml", recursive=False):
            logger.verbose("Parsing "+xmlPath)
            try:
                xml_parser = ElementTree.parse(xmlPath)
                root = xml_parser.getroot()
            except:
                logger.warning("No vulnerability found inside XML findsecbugs file.")
                continue
            results = []

            for issue in root.findall('BugInstance'):
                titlereco = ""
                descriptionreco = ""
                # to remember
                # priority_dict = {"Medium":"3","High":"4","Low":"2","Critical":"5"}
                priority_dict = {"2": "3", "1": "4", "3": "2"}

                vulnerability_code = "STAT_ANA_{}_".format(issue.get('abbrev'))
                risk_id = priority_dict[str(issue.get('priority'))]

                cwe = issue.get('cweid')

                if appName is not None:
                    title = appName+" - "+issue.find('ShortMessage').text
                else:
                    title = issue.find('ShortMessage').text


                # print (issue.get('type'))
                # print (issue.get('cweid'))
                # print (issue.find('ShortMessage').text)
                # print (issue.find('LongMessage').text)
                # print (issue.find('Class').find('Message').text)
                # print (issue.find('Class').get('classname'))
                # print (issue.find('Class').find('SourceLine').get('sourcepath'))
                # print (issue.find('Class').find('SourceLine').find('Message').text)

                description = "{}\n\n\t{}\n\tIn file: {}\n\t{}".format(
                    issue.find('LongMessage').text,
                    issue.find('Class').find('SourceLine').find('Message').text,
                    issue.find('Class').find('SourceLine').get('sourcepath'),
                    issue.find('Class').find('Message').text
                )
                # print (description)

                """
                results.append(
                    {
                        'vulnerability_code': vulnerability_code,
                        'priority': str(issue.get('priority')),
                        'risk_id': risk_id,
                        'cwe': cwe,
                        'title': title,
                        'description': description,
                        'evidence': ElementTree.tostring(issue).decode()
                    }
                )
                """

                try:
                    titlereco = "Recommandation - "+issue.get('type')
                    descriptionreco = translate(fsb_reco.fsb_reco[issue.get("type")])
                except:
                    titlereco = "Recommandation - "+issue.get('type')
                    descriptionreco = "Il est recommandé de mettre en place la recommandation suivante "+"https://findbugs.sourceforge.net/bugDescriptions_fr.html#"+issue.get('type')


                complexity_id = 1  # Facile (42/JIRA)
                #complexity_id = 2  # Modérée (42/JIRA)
                #complexity_id = 3  # Elevée (42/JIRA)
                #complexity_id = 4  # Difficile (42/JIRA)

                if risk_id == 5:
                    # Bloquant
                    impact_id = 5  # Bloquant (42) / Fort (JIRA)
                    impact = "Fort"
                    vuln_status = "Bloquant"
                    vuln_bg = "#8B0000"
                    reco_status = "Haute"
                    reco_bg = "#8B0000"
                    difficulty = "Elevée"
                elif risk_id == 4:
                    # Critique
                    impact_id = 4  # Critique (42) / Fort (JIRA)
                    impact = "Fort"
                    vuln_status = "Critique"
                    vuln_bg = "#FF8C00"
                    reco_status = "Haute"
                    reco_bg = "#8B0000"
                    difficulty = "Modérée"
                elif risk_id == 3:
                    #Majeur
                    impact_id = 3  # Important (42) / Moyen (JIRA)
                    impact = "Modéré"
                    vuln_status = "Majeur"
                    vuln_bg = "Orange"
                    reco_status = "Moyenne"
                    reco_bg = "#FF8C00"
                    difficulty = "Modérée"
                else:
                    impact_id = 1  # Faible (42) / Très faible (JIRA)
                    impact = "Faible"
                    vuln_status = "Mineur"
                    vuln_bg = "#C0C0C0"
                    reco_status = "Faible"
                    reco_bg = "#C0C0C0"
                    difficulty = "Faible"

                numvulnid = numvulnid + 1

                module_result = {
                    "scan_id": scan_id,
                    "appname": appName,
                    "module_name": "FindSecBugs",
                    "result": True,
                    "output": {
                        "module_result": {
                            "numvulnid": numvulnid,
                            "module": "AjoutManuelDeVuln",
                            "version": "0.1",
                            "titlevuln": title,
                            "description": description,
                            "reference": "CWE-"+cwe,
                            "impact": impact,
                            "difficult": difficulty,
                            "cvsslink": "https://cwe.mitre.org/data/definitions/"+cwe+".html",
                            "result": "La vulnérabilité est avérée.",
                            "titlereco": titlereco,
                            "descriptionreco": descriptionreco,
                            "responsable": "Equipe de développement"

                        }
                    },
                    "vulnerability_code": vulnerability_code,
                    "risk_id": risk_id,
                    "impact_id": impact_id,
                    "vuln_status": vuln_status,
                    "vuln_bg": vuln_bg,
                    "reco_status": reco_status,
                    "reco_bg": reco_bg,
                    "complexity_id": complexity_id
                }
                vulns.append(module_result)
    logger.success("Found "+str(len(vulns))+" vulnerabilities.")
    return vulns

def check_everything_is_good():
    nb_bin = 0
    logger.info("Checking if everything if ok...")
    for packagePath in glob.iglob(".\\apps\\*", recursive=False):
        nb_bin = 0
        logger.success("App : "+packagePath.split("\\")[-1])
        for binaryPath in glob.iglob(packagePath+"\\bin\\**",recursive=True):
            for extension in dpcheck_extensions:
                if extension in binaryPath.split("\\")[-1]:
                    logger.warning("|--- Binary : "+binaryPath)
                    nb_bin = nb_bin + 1
        if nb_bin == 0:
            logger.error("|--- No bin found, please add bins into /apps/<package_name>/bin/ folder.")
        if os.path.exists(packagePath+"\\src"):
            logger.warning("|--- Source code repository exists :" + packagePath+"\\src")
        else:
            logger.error("|--- No src code repository found, please add source code into /apps/<package_name>/src/ folder.")

    logger.warning("Is everything ok?")
    if (input("Is everything ok? [Enter : OK , else : KO]") or "y") == "y":
        return True
    else:
        return False
    return False

if __name__ == '__main__':
    options = parseArgs()
    logger.setVerbosity(options.verbose)

    vulns = []
    content = ''
    scan_id = "1"

    #Synthèse

    #vulns
    nb_vuln_bloquant = 0
    nb_vuln_critique = 0
    nb_vuln_majeur = 0
    nb_vuln_mineur = 0

    nb_reco_haute = 0
    nb_reco_moyenne = 0
    nb_reco_faible = 0

    vuln_status = ""
    reco_status = ""

    synthese = {}
    synthese['nb_vuln_bloquant'] = nb_vuln_bloquant
    synthese['nb_vuln_critique'] = nb_vuln_critique
    synthese['nb_vuln_majeur'] = nb_vuln_majeur
    synthese['nb_vuln_mineur'] = nb_vuln_mineur

    synthese['nb_reco_haute'] = nb_reco_haute
    synthese['nb_reco_moyenne'] = nb_reco_moyenne
    synthese['nb_reco_faible'] = nb_reco_faible
    synthese['nb_total_package'] = numpackage

    global nb_cve_2015
    global nb_cve_2016
    global nb_cve_2017
    global nb_cve_2018
    global nb_cve_2019
    global nb_cve_2020
    global nb_cve_2021
    global nb_cve_2022

    nb_cve_2015 = 0
    nb_cve_2016 = 0
    nb_cve_2017 = 0
    nb_cve_2018 = 0
    nb_cve_2019 = 0
    nb_cve_2020 = 0
    nb_cve_2021 = 0
    nb_cve_2022 = 0

    synthese['nb_cve_2015'] = nb_cve_2015
    synthese['nb_cve_2016'] = nb_cve_2016
    synthese['nb_cve_2017'] = nb_cve_2017
    synthese['nb_cve_2018'] = nb_cve_2018
    synthese['nb_cve_2019'] = nb_cve_2019
    synthese['nb_cve_2020'] = nb_cve_2020
    synthese['nb_cve_2021'] = nb_cve_2021
    synthese['nb_cve_2022'] = nb_cve_2022

    #Dealing with multiple JSONs
    jsonFilesPaths = []

    fsb_vulns = []
    dpcheck_vulns = []

    is_ok = check_everything_is_good()
    if is_ok:
        pass
    else:
        sys.exit(1)

    for packagePath in glob.iglob(".\\apps\\*", recursive=False):
        if not options.no_dep_check:
            from_archive_to_jsons(packagePath)
            logger.info("Collecting all JSONs files from "+packagePath+" repo.")
            jsonFilesPaths = collection_jsons_from_packagepath(packagePath)
            if jsonFilesPaths == 0 :
                pass
            else:
                logger.info("Retreive all JSONs data ...")
                for jsonFile in jsonFilesPaths:
                    logger.verbose("Json file : "+jsonFile)
                    if os.path.exists(jsonFile):
                        f = open(jsonFile)
                        content = json.load(f)
                        content = json.dumps(content)
                        f.close()
                        name = packagePath.split("\\")[-1]
                        logger.advanced("Name :"+name)
                        logger.advanced("ScanId :" + str(scan_id))
                        dpcheck_vulns = get_important_vulns(content, scan_id, name)

        if not options.no_findsecbugs:
            create_findsecbugs_xml(packagePath)
            fsb_vulns = parse_findsecbugs_results(packagePath)

        #fill all vulns
        tmp_vulns = []
        for vuln in dpcheck_vulns:
            tmp_vulns.append(vuln)
        for vuln in fsb_vulns:
            tmp_vulns.append(vuln)
        vulns.append(tmp_vulns)

    #Synthèse
    for element in vulns:
        for package in element:
            if "vuln_status" in package:
                vuln_status = package['vuln_status']
                if vuln_status == "Bloquant":
                    nb_vuln_bloquant += 1
                elif vuln_status == "Critique":
                    nb_vuln_critique += 1
                elif vuln_status == "Majeur":
                    nb_vuln_majeur += 1
                elif vuln_status == "Mineur":
                    nb_vuln_mineur += 1
                else:
                    logger.error("Problème vuln_status: "+vuln_status)
            if "reco_status" in package:
                #print("Reco status " + package['reco_status'])
                reco_status = package['reco_status']
                if reco_status == "Haute":
                    nb_reco_haute += 1
                elif reco_status == "Moyenne":
                    nb_reco_moyenne += 1
                elif reco_status == "Faible":
                    nb_reco_faible += 1
                else:
                    logger.error("Problème reco_status: "+reco_status)
    synthese = {}
    synthese['nb_vuln_bloquant'] = nb_vuln_bloquant
    synthese['nb_vuln_critique'] = nb_vuln_critique
    synthese['nb_vuln_majeur'] = nb_vuln_majeur
    synthese['nb_vuln_mineur'] = nb_vuln_mineur

    synthese['nb_reco_haute'] = nb_reco_haute
    synthese['nb_reco_moyenne'] = nb_reco_moyenne
    synthese['nb_reco_faible'] = nb_reco_faible
    synthese['nb_total_package'] = numpackage

    synthese['nb_cve_2015'] = nb_cve_2015
    synthese['nb_cve_2016'] = nb_cve_2016
    synthese['nb_cve_2017'] = nb_cve_2017
    synthese['nb_cve_2018'] = nb_cve_2018
    synthese['nb_cve_2019'] = nb_cve_2019
    synthese['nb_cve_2020'] = nb_cve_2020
    synthese['nb_cve_2021'] = nb_cve_2021
    synthese['nb_cve_2022'] = nb_cve_2022

    if options.export_docx is not None:
        display_export_synthese(options.export_docx, synthese)
        create_docx_multiple_jsons(vulns, options.export_docx, synthese)
    else:
        logger.error("No name for output docx.")






