import os
import shutil
import sys

def move_file(file_path, destination_folder, new_file_name):
    current_directory = os.path.dirname(os.path.abspath(__file__))
    destination_path = os.path.join(current_directory, destination_folder, new_file_name)
    shutil.move(file_path, destination_path)


if __name__ == '__main__':
    file_path = sys.argv[1]
    number = sys.argv[2]
    if(file_path == "=h"):
         print("LoadSamples.py {file path} {Sample number}")
    destination_folder = 'samples' #Memory image samples storage location
    new_file_name = f'{number}.vmem'
    move_file(file_path, destination_folder, new_file_name)
