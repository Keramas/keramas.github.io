---
layout: post
title: 'Hack-A-Sat CTF'
date: '2020-05-24T00:00:00.000-00:00'
author: Keramas
tags: [ctf]
---

This weekend the long-anticipated Hack-A-Sat Space Security Challenge CTF took place and it was an amazing experience. The target material of the CTF was quite advanced, and aerospace techology is not a very familiar topic to me despite having quite a passion for space. However, I was looking forward to this greatly and participated with mostly coworkers under the team `Illuminopi`. 

<img src = "/assets/images/hackasat/hackasatctflogo.png">

The challenges were very difficult, but all extremely interesting! I came away learning a TON of information about satellites, aerospace tech, and other really neat stuff. I managed to solve a couple, and wanted to share a walkthrough of how I did it.

# Track The Sat - Ground Segment

<img src = "/assets/images/hackasat/trackthesatchallenge.png">

The goal of this challenge was to 'control' the servos of a hobbiest antenna to track the movement of a given satellite over a specific period of time. 

Essentially, we need to provide it the proper power measurements based on where the satellite will be provided at a given time frame. The following is a readme file from the challenge:

```
Track-a-sat
===========

We have obtained access to the control system for a groundstation's satellite antenna. The azimuth and elevation motors are controlled by PWM signals from the controller. Given a satellite and the groundstation's location and time, we need to control the antenna to track the satellite. The motors accept duty cycles between 2457 and 7372, from 0 to 180 degrees. 

Some example control input logs were found on the system. They may be helpful to you to try to reproduce before you take control of the antenna. They seem to be in the format you need to provide. We also obtained a copy of the TLEs in use at this groundstation.

```

Connecting to the challenge over netcat the following information is received:

```bash
keramas@ubuntu:~/Documents/calendar_hint1$ nc trackthesat.satellitesabove.me 5031
Ticket please:
ticket{november1326tango:GMTF4FYSV7xTf0VKY-gxYOt_CC--N8dBcOiw6uc05UG1CZeLhnE6oetM3S8L-GWaHQ}
Track-a-sat control system
Latitude: -11.85
Longitude: -55.46
Satellite: COSMOS 2489
Start time GMT: 1586258885.980149
720 observations, one every 1 second
Waiting for your solution followed by a blank line...
```
Additionally, we are provided with a tar file which consists of similar sample challenges and their solutions. This allows us to check calculations against a valid sample set of data to make sure we are on the right track. They also give us a list of TLEs ([two-line element set](https://en.wikipedia.org/wiki/Two-line_element_set)) for several satellites. 

Based on all of this, we have the following known data points:
- Our satellite target is COSMOS 2489
- We know the coordinates of the groundstation, or where we are starting our observation
- We know the start time as well as the end time (start time + 720 seconds)

The system is looking for a solution in the following format: it is a timestamp followed by a pulse width modulation value for the azimuth, and a pulse width modulation value for the elevation to set the antenna to the correct position:
```
1586789933.820023, 6001, 2579
1586789934.820023, 5999, 2581
1586789935.820023, 5997, 2583
1586789936.820023, 5995, 2585
1586789937.820023, 5994, 2587
1586789938.820023, 5992, 2589
```

Since we have the satellite name, we can look at the TLE catalog provided and extract our satellite's TLE data:

```
COSMOS 2489             
1 39484U 13076B   20101.17452180  .00000026  00000-0  11977-3 0  9993
2 39484  82.4863 137.2077 0020900 343.7530  16.2897 12.42873420285522
```

Using the Python `ephem` library, we can use the above data to predict the azimuth and elevation angles need as the satellite travels over the course of 720 seconds.

A sample of the output for our satellite (the final timestamp), ground station, and timeframe would be the following:

```
1586259604.980149,164.0,11.4
```

However, the results are in angles and we need to convert this into PWM values for our servo. 

The challenge text mentions that we have a specific range of 2457 and 7372, which translates to 0 to 180 degrees. Using the sample solution data to look at the power values, we can run a script to check for that satellite data instead, and then cross reference the angle data with the PWM values present in the provided material. 

Based on this, it is possible to determine a ratio of power to angle where 1 degree of movement is roughly 27.3. Using this calculation, the following Python script was written. It was important to note as well that since the values returned in angles could be greater than 180 degrees, this needs to be accounted for in the Python script by subtracting 180 from these values and adjusted accordingly for power values. The COSMOS satellite did not require this calculation, however. 

```python
from pwn import *
import sys
import time
import datetime
from math import *
import ephem


class Tracker():
    # Class taken from https://gist.github.com/andresv/920f7bbf03f91a5967ee
    def __init__(self, satellite, groundstation):

        self.groundstation = ephem.Observer()
        self.groundstation.lat = groundstation[0]
        self.groundstation.lon = groundstation[1]
        self.groundstation.elevation = int(groundstation[2])

        self.satellite = ephem.readtle(satellite["name"], satellite["tle1"], satellite["tle2"])

    def set_epoch(self, epoch=time.time()):
        ''' sets epoch when parameters are observed '''

        self.groundstation.date = datetime.datetime.utcfromtimestamp(epoch)
        self.satellite.compute(self.groundstation)

    def azimuth(self):
        ''' returns satellite azimuth in degrees '''
        return degrees(self.satellite.az)

    def elevation(self):
        ''' returns satellite elevation in degrees '''
        return degrees(self.satellite.alt)

    def latitude(self):
        ''' returns satellite latitude in degrees '''
        return degrees(self.satellite.sublat)

    def longitude(self):
        ''' returns satellite longitude in degrees '''
        return degrees(self.satellite.sublong)

    def range(self):
        ''' returns satellite range in meters '''
        return self.satellite.range

    def ecef_coordinates(self):
        ''' returns satellite earth centered cartesian coordinates
            https://en.wikipedia.org/wiki/ECEF
        '''
        x, y, z = self._aer2ecef(self.azimuth(), self.elevation(), self.range(), float(self.groundstation.lat), float(self.groundstation.lon), self.groundstation.elevation)
        return x, y, z

    def _aer2ecef(self, azimuthDeg, elevationDeg, slantRange, obs_lat, obs_long, obs_alt):

        #site ecef in meters
        sitex, sitey, sitez = llh2ecef(obs_lat,obs_long,obs_alt)

        #some needed calculations
        slat = sin(radians(obs_lat))
        slon = sin(radians(obs_long))
        clat = cos(radians(obs_lat))
        clon = cos(radians(obs_long))

        azRad = radians(azimuthDeg)
        elRad = radians(elevationDeg)

        # az,el,range to sez convertion
        south  = -slantRange * cos(elRad) * cos(azRad)
        east   =  slantRange * cos(elRad) * sin(azRad)
        zenith =  slantRange * sin(elRad)

        x = ( slat * clon * south) + (-slon * east) + (clat * clon * zenith) + sitex
        y = ( slat * slon * south) + ( clon * east) + (clat * slon * zenith) + sitey
        z = (-clat *        south) + ( slat * zenith) + sitez

        return x, y, z


target = "trackthesat.satellitesabove.me"
port = 5031

r = remote(target,port)
r.recvline()
r.sendline("ticket{november1326tango:GMTF4FYSV7xTf0VKY-gxYOt_CC--N8dBcOiw6uc05UG1CZeLhnE6oetM3S8L-GWaHQ}")

print(str(r.recvuntil("line...")))

#Real values
ec1_tle = { "name": "COSMOS 2489", \
            "tle1": "1 39484U 13076B   20101.17452180  .00000026  00000-0  11977-3 0  9993", \
            "tle2": "2 39484  82.4863 137.2077 0020900 343.7530  16.2897 12.42873420285522"}

tallinn = ("-11.85", "-55.46", "0")

t = 1586258885.980149

tracker = Tracker(satellite=ec1_tle, groundstation=tallinn)

start = t
print("[+] Calculating azis and elevations.")

pwm_min = 2457
pwm_max = 7372

incremental_gain = 27.3

print("[+] Sending data - PWM | Angles")

while True:
    tracker.set_epoch(t)
    
    # Float point angle values for checking
    
    azimuth_angle = float(tracker.azimuth())
    elevation_angle = float(tracker.elevation())

    # If angles are greater than 180, we need to subtract 180
    if azimuth_angle > 180:
        azimuth_angle = azimuth_angle - 180
        pwm_azimuth = pwm_max - (azimuth_angle * incremental_gain)
    
    else:
        pwm_azimuth = (azimuth_angle * incremental_gain) + pwm_min
    

    if elevation_angle > 180:
        elevation_angle = elevation_angle - 180
        pwm_elevation = pwm_max - (elevation_angle * incremental_gain) 

    else:
        pwm_elevation = (elevation_angle * incremental_gain) + pwm_min

    # Time, azimuth and elevation in PWM whole number
    r.sendline((str(t) +","+ str(int(pwm_azimuth)) + "," + str(int(pwm_elevation))))
    print(((str(t) +","+ str(int(pwm_azimuth)) + "," + str(int(pwm_elevation)))) + " | " + (str(t) +","+ "%0.1f,%0.1f" % (tracker.azimuth(),tracker.elevation())))

    t += 1.0

    if t == (start + 720.0):
        break
        
    else:
        continue
        #time.sleep(1)

print("[+] Sending final chunk of data...")
r.sendline("\n")

r.interactive()
```

Firing this script off at the challenge server, we get our flag!

```bash
keramas@utsusemi:~/Documents/ctfs$ python3 satracker.py 
[+] Opening connection to trackthesat.satellitesabove.me on port 5031: Done
[+] Calculating azis and elevations.
[+] Sending data - PWM | Angles
1586258885.980149,3222,3441 | 1586258885.980149,28.0,36.0
1586258886.980149,3225,3444 | 1586258886.980149,28.2,36.2
1586258887.980149,3228,3447 | 1586258887.980149,28.3,36.3
1586258888.980149,3231,3450 | 1586258888.980149,28.4,36.4
1586258889.980149,3235,3454 | 1586258889.980149,28.5,36.5
[SNIP]
1586259602.980149,6931,2773 | 1586259602.980149,163.9,11.6
1586259603.980149,6932,2771 | 1586259603.980149,163.9,11.5
1586259604.980149,6933,2769 | 1586259604.980149,164.0,11.4
[+] Sending final chunk of data...
[*] Switching to interactive mode


Congratulations: flag{november1326tango:GMz_2lhVb_md4qiEywiHG23RUIOoW1WRNxP5j5kP563OeFQwAy4wH8-awHWWJNeIvudsyrP6lALeyUusPDWb8w0}

```

# Where's the Sat? - Space and Things

<img src = "/assets/images/hackasat/wheresthesatchallenge.png">

In this challenge, the goal is to respond to a series of questions for x,y,z coordinates of a satellite at a given time that is specified dynamically when you connect to the challenge server. 

In total, the server challenges you three times, and a total of 3 sets of x,y,z coordinates for three different time stamps (generated dynamically).

The material provided is a catalog of TLEs for about 30 or so different satellites. 

When connecting to the server, we also receive the following data:

```bash
Ticket please:
ticket{tango16955delta:GGfAkl_TGIxWvoEzaFeObV5DZVBgFn06Lf4Leo92CvZ7MntQlZ5ZZc9s6zcXmHjPXQ}
Please use the following time to find the correct satellite:(2020, 3, 18, 19, 44, 50.0)
Please use the following Earth Centered Inertial reference frame coordinates to find the satellite:[2136.5180087574327, -4637.4429350045, -4478.5496201641745]
Current attempt:1
What is the X coordinate at the time of:(2020, 3, 18, 7, 21, 6.0)?
2136.5180087574327 
DEBUG: 1636.402604370332
2136.5180087574327 is incorrect, please try again and enter the the X  coordinate for the satellite at (2020, 3, 18, 7, 21, 6.0).
Current attempt:2
What is the X coordinate at the time of:(2020, 3, 18, 7, 21, 6.0)?
1636.402604370332
What is the Y coordinate at the time of:(2020, 3, 18, 7, 21, 6.0)?

Please enter the proper coordinate for the satellite at (2020, 3, 18, 7, 21, 6.0).
Current attempt:3
What is the X coordinate at the time of:(2020, 3, 18, 7, 21, 6.0)?

```

Analyzing this, we know the following:
- We have a starting time.
- We have the geocentric position of the satellite at the given time.
- The challenge gives us a timestamp array.
- We get some debug feedback which helps us realize the full set of x,y,z coordinates will be needed, as well as the format it is looking for.

Putting this all together, we can use the `skyfield` Python library to perform all our calculations. 

To do this we'll do the following:
- Since we know the geocentric position and time, we can import the whole list of TLEs given to first confirm which satellite is our target by calculating the geocentric position of each one for the initially given timestamp, and then checking that value against the satellite position they give when connecting to the challenge server.
- Now that we have our target TLE data from the above check, we can recalculate the geocentric position of the satellite for each new stamp that is generated for the challenge itself. 
- Once we have the geocentric coordinates, we feed the server the x,y,z coordinates one at a time, and then recursively run the function to repeat the process until there are no more timestamps generated.

The following script (which I wrote at 4am and I had no idea what my brain was doing) accomplishes this:

```python
from pwn import *
import sys
import time
import datetime
from itertools import islice
from math import *
from skyfield.api import EarthSatellite,load,Topos

def getGeocentricFromTLE(name,line1,line2,a,b,c,d,e,f):
    ts = load.timescale()
    t = ts.utc(a, b, c, d, e, f)
    satellite = EarthSatellite(line1,line2,name,ts)
    geocentric = satellite.at(t)
    
    return geocentric.position.km
        
def next_n_lines(file_opened, N):
    return [x.strip() for x in islice(file_opened, N)]

def submitXYZ(startdata,sat_name,tle1,tle2,counter):
      
    print("[+] Grabbing requested coordinate")
    newTimeStamp = str(startdata).split("of:")[1].strip("?\'").strip("(").strip(")").replace(" ","")
    print("Requested time: ", newTimeStamp)
    a = int(newTimeStamp.split(",")[0])
    b = int(newTimeStamp.split(",")[1])
    c = int(newTimeStamp.split(",")[2])
    d = int(newTimeStamp.split(",")[3])
    e = int(newTimeStamp.split(",")[4])
    f = int(newTimeStamp.split(",")[5].strip(".0"))
    
    new_geo = getGeocentricFromTLE(sat_name,tle1,tle2,a,b,c,d,e,f)
    
    #Give X
    r.sendline(str(new_geo[0]))

    #Give Y
    r.recvuntil("?")
    r.sendline(str(new_geo[1]))

    #Give Z
    r.recvuntil("?")
    r.sendline(str(new_geo[2]))
    
    print("Sent: ", new_geo[0], new_geo[1], new_geo[2])
    
    counter += 1
    if counter == 3:
        return

    else:
        next_time = r.recvuntil("?")
        submitXYZ(next_time,sat_name,tle1,tle2,counter) 


target = "where.satellitesabove.me"
port = 5021

r = remote(target,port)
r.recvline()
r.sendline("ticket{tango16955delta:GGfAkl_TGIxWvoEzaFeObV5DZVBgFn06Lf4Leo92CvZ7MntQlZ5ZZc9s6zcXmHjPXQ}")

a = 2020
b = 3
c = 18
d = 19
e = 44
f = 50

# Geocentric starting point
starting_x = 2136.5180087574327
starting_y = -4637.4429350045
starting_z = -4478.5496201641745

print("[+] Determining satellite from TLE database based on starting time and coordinates...")
with open("all_tles", 'r') as stations:
    while True:
        tle_data = next_n_lines(stations, 3)
        sat_name = tle_data[0]
        tle1 = tle_data[1]
        tle2 = tle_data[2]
        geo = getGeocentricFromTLE(sat_name,tle1,tle2,a,b,c,d,e,f)
        
        if geo[0] == starting_x and geo[1] == starting_y and geo[2] == starting_z:
            print("[+] Satellite identified as", sat_name)
            break
    
        else:
            continue

startdata = r.recvuntil("?")

counter = 0
submitXYZ(startdata,sat_name,tle1,tle2,counter)
r.interactive()
```

Firing this off at the challenge server, we get the flag!

```bash
keramas@utsusemi:~/Documents/ctfs$ python3 wheresthesat.py 
[+] Opening connection to where.satellitesabove.me on port 5021: Done
[+] Determining satellite from TLE database based on starting time and coordinates...
[+] Satellite identified as PINOT
[+] Grabbing requested coordinate
Requested time:  2020,3,18,17,33,58.0
Sent:  -3928.2924085994346 1485.1345837164286 5320.5491682904885
[+] Grabbing requested coordinate
Requested time:  2020,3,18,5,46,26.0
Sent:  1085.5439354074572 -5798.646016153185 -3366.5231568592553
[+] Grabbing requested coordinate
Requested time:  2020,3,18,15,5,11.0
Sent:  1739.122395778712 -5120.011031140808 -4110.114920436351
[*] Switching to interactive mode

The Z axis coordinate for (2020, 3, 18, 15, 5, 11.0) is correct!
flag{tango16955delta:GGAt_2NW6JUP9UyAB4C2I793XhHGT4rP9PsTBO227Fjzj4BSlht49XqPYgDzz7_TTqYQro1OmkblmVCxfPSjK9k}
```
