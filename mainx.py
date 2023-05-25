import os
import subprocess
import sys

def execute_script(script_path, args):
    try:
        command = ['python3', script_path] + args
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(command)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print(f'Error executing script. Return code: {process.returncode}\nError message: {stderr.decode()}')
            return None
        else:
            return stdout.decode()

    except Exception as e:
        print(f'An error occurred while trying to execute the script: {e}')
        return None

def MMI_Heuristics(result1, result2, c):
    if c=="compare":
        r = list(set(result1) - set(result2)) + list(set(result2) - set(result1))
        return r
    
    elif c=="Pageout":
        pass
    elif c=="Pageout":
        pass

    return "Invalid"

if __name__ == '__main__':
    current_directory = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(current_directory, 'Volatility3', 'vol.py')



    params = sys.argv[1]
    if params == "-p1":
        script_args = ['-f','samples/1.vmem','windows.pstree.PsTree']  
        script_output = execute_script(script_path, script_args)
        print(script_output)
    elif params == "-p2":
        script_args = ['-f','samples/2.vmem','windows.pstree.PsTree']  
        script_output = execute_script(script_path, script_args)
        print(script_output)
    elif params == "-i":
        script_args = ['-f','samples/2.vmem','windows.info']  
        script_output = execute_script(script_path, script_args)
        print(script_output)
    elif params == "-MMI":
        # Start of the MMI Algorithm! Bases of all heuristics and anomaly detection of multiple memory-images
        # Works on the base of volatility framework for image information extraction

        script_args = ['-f','samples/1.vmem','windows.malfind.Malfind'] 
        output1 = execute_script(script_path, script_args)
        print(output1)

        script_args = ['-f','samples/2.vmem','windows.malfind.Malfind'] 
        output2 = execute_script(script_path, script_args)
        print(output2)

        if output1 is not None and output2 is not None:
            image1_lines = output1.split('\n')
            image2_lines = output2.split('\n')

        results = MMI_Heuristics(image1_lines, image2_lines,"compare")
        if results:
            print("Found differences:")
            print("-"*50)
            for r in results:
                print(r)
        else:
            print("No Malware between images!")

    else:
        print("Give proper flags!")
