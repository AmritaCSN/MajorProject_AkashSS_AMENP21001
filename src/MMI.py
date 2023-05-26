import os
import subprocess
import sys
import vad
import dlllist
import confidence
import status
import anomaly
import blacklist

debug = 1
c = confidence.Confidence()

def execute_script(script_path, args):
    try:
        command = ['python3', script_path] + args
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if(args[2] == "windows.vadinfo.VadInfo"):
            status.processing("vad")
        if(args[2] == "windows.malfind.Malfind"):
            status.processing("mal")
        if(args[2] == "dlllist"):
            status.processing("dll")
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
    elif c=="DLL":
        pass
    elif c=="DLL":
        pass

    return "Invalid"

if __name__ == '__main__':
    current_directory = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(current_directory, 'Volatility3', 'vol.py')



    params = sys.argv[1]
    if params == "-h":
        print("MMI.py {flag} \n -p{n}: process tree info for sample no.n \n -MMI: Identify detected fileless malware using MMI algorithm \n ")
    #Process tree information of individual memory images
    elif params == "-p1":
        script_args = ['-f','samples/1.vmem','windows.pstree.PsTree']  
        script_output = execute_script(script_path, script_args)
        print(script_output)
    elif params == "-p2":
        script_args = ['-f','samples/2.vmem','windows.pstree.PsTree']  
        script_output = execute_script(script_path, script_args)
        print(script_output)
    elif params == "-p3":
        script_args = ['-f','samples/3.vmem','windows.pstree.PsTree']  
        script_output = execute_script(script_path, script_args)
        print(script_output)
    elif params == "-p4":
        script_args = ['-f','samples/4.vmem','windows.pstree.PsTree']  
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
        maloutput1 = execute_script(script_path, script_args)
        if(debug):
         print(maloutput1)
         #status.message("malfind1",anomaly.count_lines(maloutput1))

        script_args = ['-f','samples/2.vmem','windows.malfind.Malfind'] 
        maloutput2 = execute_script(script_path, script_args)
        if(debug):
         print(maloutput2)
         #status.message("malfind2",anomaly.count_lines(maloutput2))

        s = 0
        minentry = min(anomaly.count_lines(maloutput1),anomaly.count_lines(maloutput2))
        if minentry > 60:
            s = 70
        c.add_decision("malicious",confidence.confidence_score(anomaly.count_lines(maloutput1),anomaly.count_lines(maloutput2),s))


        if maloutput1 is not None and maloutput2 is not None:
            image1_lines = maloutput1.split('\n')
            image2_lines = maloutput2.split('\n')

        status.processing("MMI")
        Malwarediff = MMI_Heuristics(image1_lines, image2_lines,"compare")

        script_args = ['-f','samples/1.vmem','windows.vadinfo.VadInfo'] 
        vad1 = execute_script(script_path, script_args)
        if(debug):
         print(vad)
         #status.message("vad1",anomaly.count_lines(vad1))

        script_args = ['-f','samples/2.vmem','windows.vadinfo.VadInfo'] 
        vad2 = execute_script(script_path, script_args)
        if(debug):
         print(vad2)
         #status.message("vad2",anomaly.count_lines(vad2))

        s1 = 0 
        Vadiff = vad.compare_vadinfo(vad1,vad2)
        if(Vadiff > 5): #VAD remapping attacks/Page out happened
            s1 = 50
        c.add_decision("vadremap",confidence.confidence_score(anomaly.count_lines(vad1),anomaly.count_lines(vad2), s1))


      

        script_args = ['-f','samples/1.vmem','dlllist'] 
        dll1 = execute_script(script_path, script_args)


        script_args = ['-f','samples/2.vmem','dlllist'] 
        dll2 = execute_script(script_path, script_args)

        #print(dll1)
        s2 = 0
        dlldiff = dlllist.compare_dlllist(dll1,dll2)
        for i in dlldiff:
            if(blacklist.islisted(i)):
                s2 += 15
                if(s2 == 45):
                    break
        c.add_decision("DLL",confidence.confidence_score(anomaly.count_lines(dll1),anomaly.count_lines(dll2), s1))

        print(c.decisions)

        status.processing("result")
        conclusion = False
        for i in c.decisions:
            if i[1] > 90: #confidence value 
                conclusion = True
        if (c.calculate_average_confidence() > 60):
            conclusion = True

        print("\n\n")
        status.Malware(conclusion)

        #print(Vadiff)

    else:
        print("Give proper flags!")
