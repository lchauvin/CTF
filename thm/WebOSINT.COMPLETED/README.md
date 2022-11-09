# WebOSINT

Laurent Chauvin | November 09, 2022

## Resources

[1] https://lookup.icann.org/lookup

[2] https://archive.org/

[3] https://viewdns.info/

[4] https://www.iphistory.ch/en/

## Progress

### Task 1 : When A Website Does Not Exist

### Task 2 : Whois Registration

1. What is the name of the company the domain was registered with?

Using [1], we can find the name of the company is <mark>NAMECHEAP INC</mark>

2. What phone number is listed for the registration company? (do not include country code or special characters/spaces)

On the same website, looking at the RAW Registry RDAP Response, we can find the phone number is <mark>6613102107</mark>

Not sure why it's not the same as listed in the Domain or Contact Information.

3. What is the first nameserver listed for the site?

The first nameserver listed is <mark>NS1.BRAINYDNS.COM</mark>

4. What is listed for the name of the registrant?

The name of the registrant is <mark>Redacted for Privacy</mark>

5. What country is listed for the registrant?

The registrant is listed in Iceland, however, it didn't work. After checking a solution, it turns out the answer is <mark>Panama</mark>. I think the domain name has changed owner since the challenge has been created.

### Task 3 : Ghosts of Websites Past

1. What is the first name of the blog's author?

Using [2] and this url 'https://web.archive.org/web/20160414005938/http://www.republicofkoffee.com/index.php/2015/06/26/cafe-zorba-chosun-university-area/' we see the author's firstname is <mark>Steve</mark>

2. What city and country was the author writing from?

From the same page, in the recent posts, we can see 'Cafe Zorba, Chosun University area', which is located in <mark>Gwangju, South Korea</mark>

3. [Research] What is the name (in English) of the temple inside the National Park the author frequently visits?

When looking at the Chosun University on Google Maps, we can see there is the Mudeungsan National Park next to it, with the <mark>Jeungsimsa Temple</mark> inside.

### Task 4 : Digging into DNS

1. What was RepublicOfKoffee.com's IP address as of October 2016?

Using this adress (can be very slow to load) https://viewdns.info/iphistory/?domain=republicofkoffee.com we find the IP address as of October 2016 is <mark>173.248.188.152</mark>

2. Based on the other domains hosted on the same IP address, what kind of hosting service can we safely assume our target uses?

Given the other hosts on the IP, we can assume it's a <mark>shared</mark> host.

3. How many times has the IP address changed in the history of the domain?

At the time of the challenge (created in 2021) we can see 3 different IPs in the history. However, the answer is <mark>4</mark>. Looking at a writeup, we can see the IP history was different. The room is not up-to-date.

### Task 5 : Taking Off The Training Wheels

1. What is the second nameserver listed for the domain?

Using [1] we can find the second nameserver is <mark>NS2.HEAT.NET</mark>

2. What IP address was the domain listed on as of December 2011?

Using [3] or [4], we can find the IP was <mark>72.52.192.240</mark>

3. Based on domains that share the same IP, what kind of hosting service is the domain owner using?

Using a reverse lookup https://viewdns.info/reverseip/?host=heat.net&t=1 we can see it's a <mark>shared</mark> domain hosting service

4. On what date did was the site first captured by the internet archive? (MM/DD/YY format)

Using [2] we can see the first capture was on June 1st 1997, or <mark>06/01/97</mark>

5. What is the first sentence of the first body paragraph from the final capture of 2001?

The last capture of 2001 was in July 6th, we can read on the first paragrah <mark>After years of great online gaming, it’s time to say good-bye.</mark>

6. Using your search engine skills, what was the name of the company that was responsible for the original version of the site? 

Going to the first snapshot in 1997, we can see the header 'Heat: Internet Game Network'. When Googling that, we find 'Heat.net, stylized HEAT.NET, was an online PC gaming system produced by <mark>SegaSoft</mark> and launched in 1997 during Bernie Stolar's tenure as SEGA of America president.'

7. What does the first header on the site on the last capture of 2010 say?

The last snapshot of 2010 is on December 30th, and the header reads <mark>Heat.net – Heating and Cooling</mark>

### Task 6 : Taking A Peek Under The Hood Of A Website

1. How many internal links are in the text of the article?

Just hovering the mouse on links show the target of the link. I found <mark>5</mark> internal links

2. How many external links are in the text of the article?

And <mark>1</mark> external link

3. Website in the article's only external link (that isn't an ad)

<mark>purchase.org</mark>

4. Try to find the Google Analytics code linked to the site

In the source code, we can find the Google Analytics code that starts with UA: <mark>UA-251372-24</mark>

5. Is the the Google Analytics code in use on another website? Yay or nay

Going to https://www.nerdydata.com/reports/ua-251372-24/875cc063-fa67-45f3-afd6-fb4bfa259d5b we can see this code is not used by other websites too: <mark>nay</mark>

6. Does the link to this website have any obvious affiliate codes embedded with it? Yay or Nay

<mark>Nay</mark>

### Task 7 : Final Exam: Connect the Dots

1. Use the tools in Task 4 to confirm the link between the two sites. Try hard to figure it out without the hint.

Doing an IP history on [3] for heat.net and purchase.org, we can see a common owner

Heat.net:
```
72.52.192.240	Lansing - United States	Liquid Web	2011-12-19
```

Purchase.org
```
72.52.193.127	Lansing - United States	Liquid Web	2012-11-16
```

Similar IP address, same location, same name, almost 1 year apart.

When doing a IP Location Finder, we can confirm they are from the same place

72.52.193.127
```
City:         Lansing
Zip Code:     48917
Region Code:  MI
Region Name:  Michigan
Country Code: US
Country Name: United States
Latitude:     42.7348
Longitude:    -84.6245
GMT Offset:   
DST Offset:   
```

72.52.192.240
```
City:         Lansing
Zip Code:     48917
Region Code:  MI
Region Name:  Michigan
Country Code: US
Country Name: United States
Latitude:     42.7348
Longitude:    -84.6245
GMT Offset:   
DST Offset:   
```

Probably the location of Liquid Web, the host.

The answer seems to be 'Liquid Web' but I wasn't sure what to do with the ```*.*.*``` then I thought about companies that are L.L.C, so I tried <mark>Liquid Web, L.L.C</mark>

### Task 8 : Debriefing

### Task 9 : Wrap-up
