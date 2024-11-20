import argparse
import logging
import subprocess
import csv
from datetime import date
# import pyyaml

TRIVY = "aquasec/trivy"

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel('DEBUG')

# TODO: define a cve object class for easy writing of lines int the csv file.
# Use existing code examples and modify as needed rather than write from scratch. 

def initArgs():
    parser = argparse.ArgumentParser(
        prog='Helm Chart Vulnerabitily Report',
        description='Given a chart and version, scans included images for vulnerabilities',
        add_help=True
    )
    parser.add_argument('-chart', '-c', help="Helm chart name in format repo/chart",required=True)
    parser.add_argument(
        '-version', '-v', help="Chart version", required=True)
    args = parser.parse_args()
    return args
       
#This function was genereated by ChatGPT.
# I renamed it, added the chart/version params, and the helmCmd variable.
# vars and command params were replaced to get the desired result. 
# I also had to add shell=True|False as needed. This caused me issues and took a bit of troubleshooting to figure out
def getChartImages(chart, chart_version):
    # Call the Helm command with subprocess
    helm_process = subprocess.Popen(['helm', 'template', chart, '--version', chart_version], stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True, shell=False)
    #Pipe the output to grep
    grep_process = subprocess.Popen(['grep', 'image:'], stdin=helm_process.stdout, stdout=subprocess.PIPE, text=True, shell=False)
    # Pipe the output to awk
    awk_process = subprocess.Popen(['awk', '{print $2}'], stdin=grep_process.stdout, stdout=subprocess.PIPE, text=True,  shell=False)
    # Pipe the output to sort
    sort_process = subprocess.Popen(['sort'], stdin=awk_process.stdout, stdout=subprocess.PIPE, text=True,  shell=False)
    # # Pipe the output to uniq
    uniq_process = subprocess.Popen(['uniq'], stdin=sort_process.stdout, stdout=subprocess.PIPE, text=True,  shell=False)
    # Close the standard input for previous processes
    helm_process.stdout.close()
    grep_process.stdout.close()
    awk_process.stdout.close()
    sort_process.stdout.close()

    #TODO: there was a better way I could have done this using pyyaml.
    # something like modifying this code generated from ChatGPT
    '''
    def find_images_in_yaml(file_path):
    with open(file_path, 'r') as file:
        # Parse the YAML file
        data = yaml.safe_load(file)

    # Function to recursively search for "image:"
    def search_for_images(data):
        if isinstance(data, dict):
            for key, value in data.items():
                if key == "image":
                    print(f'Found image: {value}')
                search_for_images(value)
        elif isinstance(data, list):
            for item in data:
                search_for_images(item)

    search_for_images(data)
    '''
    # Get the final output
    output, errors = uniq_process.communicate()

    if errors:
        logger.error(f'Error: {errors}')
        return None
    elif output:
        images = [output]
        return images
    else: 
        return None

def runTrivyScan(imagename):
    # Run Trivy docker container
    trivy_proc = subprocess.Popen(['docker', 'run', TRIVY , 'image', imagename, '-f', 'json'], stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True, shell=False)
    # Get the output from trivy as json
    output, errors = trivy_proc.communicate()

    #TODO: fix errors when trivy scan reports files too large. (e.g. try bitnami/grafana)

    if errors:
        logger.error(f'Error: {errors}')
        return None
    elif output:
        return output
    else: 
        return None

if __name__ == "__main__":
    logger.info("Running...")
    args = initArgs()
    chart = args.chart
    chart_version = args.version
    
    try:
        # Retrieve helm chart and list each container image included
        chart_images = getChartImages(chart, chart_version)
        print(chart_images)
        if chart_images == None: 
            logger.info(f"No images found for chart {chart}:{chart_version}")
            exit()
        
        logger.debug(f"chart_images: {chart_images}")
        for img in chart_images: 
            imgparts = img.split('/')
            imgname = imgparts[-1]
            logger.debug(f"imgname: {imgname}")
            
            #BUG: currently the scan will fail because the parsing of the image name into an image:version format trivy understands is incorrect
            # I ran out of time trying to troubleshoot this. 
            scan_json = runTrivyScan(imgname) # trivy uses format flag to output as json
            
            #TODO: json.load(scan_json)
            
            #TODO: create a list of cve results from the json output where severity >= medium
            #TODO: store them as cve objects from a custom class

            #TODO: for each cve from above generate a cve line object

            #TODO: use csv.writer to output a csv file,using datestamp as the filename prefix.
            timestamp = date.today()
            outfile = f"{timestamp}-trivy-scan-{chart}-{chart_version}.csv"
            logger.info(f"Output results to {outfile}")
        
    except Exception as ex:
         logger.error(ex)
         exit(1)