# SDN-MaliciousFlowsQuarantine

## Set up

Once imported the project you can retrieve the * *unipi* * directory and place it inside the  following path:
* /home/student/floodlight/src/main/java/net/floodlightcontroller * 

Then you can copy the *mininet* directory in the following path:
* /home/student *

Now you are ready to run the application:

1. from the home directory you can type the following commands to start mininet:
```
sudo python mininet/topology.py
```
2. from the *floodlight*  directory you can type the following commands to start the controller:
```
ant run
```
3. from the home directory you can type the following commands to start the demo:
```
python mininet/demo.py
```

**NOTE**: The instructions are meant to be executed on the VM of the course.

## Contributors

- Tommaso Baldi [@balditommaso](https://github.com/balditommaso)
