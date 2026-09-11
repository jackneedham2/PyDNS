# What is this?

This is a really small DNS client written in python using UDP sockets. All the encoding and decoding logic for the packets is implemented by hand.

# Why does it exist?

I wanted to learn about how DNS works on a deeper level, so I had a go at writing own client, with RFC 1035 as my guide. This has the added benefit of sharpening my Python skills. 

# Who should use this?

Nobody! Python has a much better DNS implementation built in, called dnspython. This is just a learning / portfolio project


# But how do you use it, should you wish to?

The simplest way to use this is to use the CLI. You can do this by running

```python3 pydns.py domain ip```

Where domain is the domain name you wish to query, and ip is the ip of your DNS server.

By default, an A record is sent out. However, you can specify a different QType by adding this onto the end of your command, like so:

```python3 pydns.py domain ip qtype```

So, for example, here's the output of a query for the A records of the domain google.com from the server at 1.1.1.1.


```
python3 pydns.py "google.com" 1.1.1.1   

RESPONSE
============
  Transaction ID      : 8738
    QR      : Response
    OPCODE  : QUERY
    AA      : False
    TC      : False
    RD      : True
    RA      : True
    Z       : 0
    RCODE   : No Error
  Num Questions       : 1
  Num Answer RRs      : 6
  Num Authority RRs   : 0
  Num Additional RRs  : 0
  Question            : google.com
  QType               : A
  QClass              : IN


ANSWERS:
============
  #   Domain       Type  Class  TTL   Data Length  Data
  1   google.com   A     IN     245   4            142.250.151.138
  2   google.com   A     IN     245   4            142.250.151.101
  3   google.com   A     IN     245   4            142.250.151.139
  4   google.com   A     IN     245   4            142.250.151.113
  5   google.com   A     IN     245   4            142.250.151.100
  6   google.com   A     IN     245   4            142.250.151.102

 ```

# What have I implemented?

I've implemented encoding and decoding logic for DNS query and response packets. So, the script can take a DNS query in dictionary format, encode this into DNS bytes (as per RFC 1035), send this to a DNS server, decode the response and return back another dictionary with answers appeneded.

# What have I not implemented?

As mentioned, this is a toy project for leearning, so there are many limitations. Here's a couple of the most important ones.

I've only implemented parsing for answer data that is in the format of an IPv4 address. So if you query a record with any other data format, you will just get raw unformatted bytes in response.

In addition, I've only implemented formatting for A records, so if you pass in a different qtype, you will just get the whole response printed as a dictionary object.

You can see both of these limitations in action in the example below:


```
python3 pydns.py "google.com" 1.1.1.1 MX
Warning: parsing for QTYPE MX is not currently supported. Raw bytes will be returned.
{'Transaction ID': 8738,
 'Flags': {'QR': 'Response',
           'OPCODE': 'QUERY',
           'AA': False,
           'TC': False,
           'RD': True,
           'RA': True,
           'Z': 0,
           'RCODE': 'No Error'},
 'Num Questions': 1,
 'Num Answer RRs': 1,
 'Num Authority RRs': 0,
 'Num Additional RRs': 0,
 'Question': 'google.com',
 'QType': 'MX',
 'QClass': 'IN',
 'Answers': [{'Domain': 'google.com',
              'Type': 'MX',
              'Class': 'IN',
              'TTL': 281,
              'Data Length': 9,
              'Data': b'\x00\n\x04smtp\xc0\x0c'}]}
```


