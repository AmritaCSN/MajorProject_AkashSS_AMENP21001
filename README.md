# MMI
MMI algorithm utilizing memory foreniscs to detect fileless malwares in multiple memory images. This algorithm works by analyzing memory images in .VMEM format, which can be acquired from virtual machines.

## Dependencies
- Clone [Volatility framework](https://github.com/volatilityfoundation/volatility3) into the root directory
- Create a 'samples' folder to load the memory-images for the MMI algorithm.
 
## Steps to run the MMI algorithm 
1/ Execute **LoadSamples.py** {image path} {image number} to load the ``.VMEM`` memory images into the MMI algorithm's system.\
2/ Ensure integrity of the loaded memory-images using ``python3 MMI.py -i``\
3/ Execute MMI algorithm using -MMI flag: ``python3 MMI.py -MMI``\
4/ Result would indicate if the fileless malware is present or not

![](https://github.com/AmritaCSN/MajorProject_AkashSS_AMENP21001/blob/main/src/Architectual%20diagram.png)
