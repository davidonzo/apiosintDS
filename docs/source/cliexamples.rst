============================
Command Line examples
============================

.. code-block:: bash

	~$ apiosintDS 
	usage: apiosintDS [-h] [-e [IPv4|domain|url|hash]] [-f /path/to/file.txt] [-st]
			  [-o /path/to/output.json] [-p] [-nc] [-v] 
			  [-c] [-cd /path/to/cachedir] [-ct [0-9]] [-cc]
        		  [-ld /path/to/git/clone/Threat-Intel/] [-ll [DEBUG|INFO|WARNING|ERROR|CRITICAL]]
        		  [-l /path/to/logfile.log] [-lc] [-i] [-s] [-vv]
	apiosintDS: error: No targets selected! Please, specify one option between --entity and --file.
	Try option -h or --help.

One item using :confval:`--pretty`
==================================
.. code-block:: bash

	$ apiosintDS -e h[REMOVED]p://193.35.18.147/bins/k.arm -st -p -nc
		      _           _       _   ____  ____  
	   __ _ _ __ (_) ___  ___(_)_ __ | |_|  _ \/ ___| 
	  / _` | '_ \| |/ _ \/ __| | '_ \| __| | | \___ \ 
	 | (_| | |_) | | (_) \__ \ | | | | |_| |_| |___) |
	  \__,_| .__/|_|\___/|___/_|_| |_|\__|____/|____/ v.2.0.3
	       |_|OSINT.DigitalSide.IT Threat-Intel Repository                             

	 Submission summary
	  -------------------------------------------------------
	 | Items parsed: 1 | Items submitted: 1 | Items found: 1 | 
	  -------------------------------------------------------
	 | Invalid(s):   0 | URL(s):          1 | URL(s):      1 | 
	 | Duplicate(s): 0 | Hash(es):        0 | Hash(es):    0 | 
	 | Not found:    0 | Domain(s):       0 | Domain(s):   0 | 
	 |                 | IP(s):           0 | IP(s):       0 | 
	  -------------------------------------------------------
	  ----------------------------------------------------------------------------
	 | hXXp://193.35.18.147/bins/k.arm                                            | 
	  ----------------------------------------------------------------------------
	 | TLP:white | First Seen 2023-07-06 07:36:02 | Last Seen 2023-07-06 07:36:02 | 
	  ----------------------------------------------------------------------------
	 | Filename: k.arm                                                            | 
	  ----------------------------------------------------------------------------
	 | MD5:    bc152acad73829358847e5f5bbf3edc0                                   | 
	 | SHA1:   f2e26e44709ba5a9766c3c00226bdb663ede5957                           | 
	 | SHA256: c8b0e1c5fa98bb407fe5bd3f2760b0ec2e5e33db0cee10a0085cac4505ef16cc   | 
	  ----------------------------------------------------------------------------
	 | Size: 244647 | Type: application/x-executable | Observed: 1 | VT: 34/61    | 
	  ----------------------------------------------------------------------------
	 | Observation time frame: N/A                                                | 
	  ----------------------------------------------------------------------------
	 | STIX network indicators: URLs => 1 | Domains => 0 | IPs: 1                 | 
	  ----------------------------------------------------------------------------
	  Online Reports (availability depends on data retention)
	  -> MISP EVENT: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/f5e313d2-3d64-4d0f-af77-37a925bcd08f.json
	  -> MISP CSV:   https://osint.digitalside.it/Threat-Intel/csv/f5e313d2-3d64-4d0f-af77-37a925bcd08f.csv
	  -> DS Report:  https://osint.digitalside.it/report/bc152acad73829358847e5f5bbf3edc0.html
	  -> STIX:       https://osint.digitalside.it/Threat-Intel/stix2/bc152acad73829358847e5f5bbf3edc0.json
	#############################################################################


Multiple items using :confval:`--file` with :confval:`--pretty` output 
======================================================================

Example file ioc.txt.

.. code-block:: bash

	~$ cat ioc.txt 
	7cb796c875cccc9233d82854a4e2fdf0
	monke.re

Response.

.. code-block:: bash

	~$ apiosintDS -f ioc.txt -p -nc -st
		
		      _           _       _   ____  ____  
	   __ _ _ __ (_) ___  ___(_)_ __ | |_|  _ \/ ___| 
	  / _` | '_ \| |/ _ \/ __| | '_ \| __| | | \___ \ 
	 | (_| | |_) | | (_) \__ \ | | | | |_| |_| |___) |
	  \__,_| .__/|_|\___/|___/_|_| |_|\__|____/|____/ v.2.0.3
	       |_|OSINT.DigitalSide.IT Threat-Intel Repository                             

	 Submission summary
	  -------------------------------------------------------
	 | Items parsed: 2 | Items submitted: 2 | Items found: 2 | 
	  -------------------------------------------------------
	 | Invalid(s):   0 | URL(s):          0 | URL(s):      0 | 
	 | Duplicate(s): 0 | Hash(es):        1 | Hash(es):    1 | 
	 | Not found:    0 | Domain(s):       1 | Domain(s):   1 | 
	 |                 | IP(s):           0 | IP(s):       0 | 
	  -------------------------------------------------------
	  ----------------------------------------------------------------------------
	 | 7cb796c875cccc9233d82854a4e2fdf0                                           | 
	  ----------------------------------------------------------------------------
	 | TLP:white | First Seen 2023-07-04 09:33:03 | Last Seen 2023-07-04 09:33:03 | 
	  ----------------------------------------------------------------------------
	 | Filename: plugmanzx.exe                                                    | 
	  ----------------------------------------------------------------------------
	 | MD5:    7cb796c875cccc9233d82854a4e2fdf0                                   | 
	 | SHA1:   158514acfa87d0b99e2af07a28004480bbf66e83                           | 
	 | SHA256: 49e64d72d5ed4fb7967da4b6851d94cdceffe4ba0316587767a13901fe580239   | 
	  ----------------------------------------------------------------------------
	 | Size: 924672 | Type: application/x-dosexec | Observed: 1 | VT: 32/71       | 
	  ----------------------------------------------------------------------------
	 | Observation time frame: N/A                                                | 
	  ----------------------------------------------------------------------------
	 | STIX network indicators: URLs => 1 | Domains => 0 | IPs: 1                 | 
	  ----------------------------------------------------------------------------
	  Online Reports (availability depends on data retention)
	  -> MISP EVENT: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/d6146389-4294-4a41-b4ca-6e74c74b7f8b.json
	  -> MISP CSV:   https://osint.digitalside.it/Threat-Intel/csv/d6146389-4294-4a41-b4ca-6e74c74b7f8b.csv
	  -> DS Report:  https://osint.digitalside.it/report/7cb796c875cccc9233d82854a4e2fdf0.html
	  -> STIX:       https://osint.digitalside.it/Threat-Intel/stix2/7cb796c875cccc9233d82854a4e2fdf0.json
	#############################################################################

	  ---------------------------------------------------------------------------
	 | monke[.]re - Related URL(s) 2                                              | 
	  ---------------------------------------------------------------------------
	  ----------------------------------------------------------------------------
	 | hXXp://monke.re/arm7                                                       | 
	  ----------------------------------------------------------------------------
	 | TLP:white | First Seen 2023-07-06 23:51:01 | Last Seen 2023-07-06 23:51:01 | 
	  ----------------------------------------------------------------------------
	 | Filename: arm7                                                             | 
	  ----------------------------------------------------------------------------
	 | MD5:    318323c9da34bf25833f7da32eab23d6                                   | 
	 | SHA1:   e2bb927b08ebcbaad8f304d02309af776312c9bf                           | 
	 | SHA256: bb1f9e108daa389e62b79067d1cdbef548f9934c9cc85a92565da7063cf36f89   | 
	  ----------------------------------------------------------------------------
	 | Size: 57148 | Type: application/x-executable | Observed: 1 | VT: 14/61     | 
	  ----------------------------------------------------------------------------
	 | Observation time frame: N/A                                                | 
	  ----------------------------------------------------------------------------
	 | STIX network indicators: URLs => 1 | Domains => 1 | IPs: 0                 | 
	  ----------------------------------------------------------------------------
	  Online Reports (availability depends on data retention)
	  -> MISP EVENT: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/f83d06e6-aa2f-452e-a19d-59d40e874355.json
	  -> MISP CSV:   https://osint.digitalside.it/Threat-Intel/csv/f83d06e6-aa2f-452e-a19d-59d40e874355.csv
	  -> DS Report:  https://osint.digitalside.it/report/318323c9da34bf25833f7da32eab23d6.html
	  -> STIX:       https://osint.digitalside.it/Threat-Intel/stix2/318323c9da34bf25833f7da32eab23d6.json
	  ----------------------------------------------------------------------------
	 | hXXp://monke.re/mips                                                       | 
	  ----------------------------------------------------------------------------
	 | TLP:white | First Seen 2023-07-07 00:31:02 | Last Seen 2023-07-07 00:31:02 | 
	  ----------------------------------------------------------------------------
	 | Filename: mips                                                             | 
	  ----------------------------------------------------------------------------
	 | MD5:    579081f528d9279a87b298b9838c377b                                   | 
	 | SHA1:   45048073aad5997881dffe41e32f9b17beb1c2e1                           | 
	 | SHA256: 8186a1d140631e6391978c08c35e01efb58963f65a86fddf7dec44eec7681c6b   | 
	  ----------------------------------------------------------------------------
	 | Size: 48272 | Type: application/x-executable | Observed: 1 | VT: 12/61     | 
	  ----------------------------------------------------------------------------
	 | Observation time frame: N/A                                                | 
	  ----------------------------------------------------------------------------
	 | STIX network indicators: URLs => 1 | Domains => 1 | IPs: 0                 | 
	  ----------------------------------------------------------------------------
	  Online Reports (availability depends on data retention)
	  -> MISP EVENT: https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/d01c2ad1-0e2c-4b26-9725-f8a86025bd75.json
	  -> MISP CSV:   https://osint.digitalside.it/Threat-Intel/csv/d01c2ad1-0e2c-4b26-9725-f8a86025bd75.csv
	  -> DS Report:  https://osint.digitalside.it/report/579081f528d9279a87b298b9838c377b.html
	  -> STIX:       https://osint.digitalside.it/Threat-Intel/stix2/579081f528d9279a87b298b9838c377b.json
	##################################################################################################################################

Multiple items using :confval:`--file` with ``JSON`` output 
===========================================================

Example file ioc.txt.

.. code-block:: bash

	~$ cat ioc.txt 
	7cb796c875cccc9233d82854a4e2fdf0
	monke.re

Response.

.. code-block:: bash

	~$ apiosintDS -f ioc.txt -st
	
	{
	    "domain": {
		"items": [
		    {
		        "item": "monke.re",
		        "response": true,
		        "response_text": "Item found in latestdomains.txt list",
		        "related_urls": [
		            {
		                "url": "h[REMOVED]p://monke.re/arm7",
		                "hashes": {
		                    "md5": "318323c9da34bf25833f7da32eab23d6",
		                    "sha1": "e2bb927b08ebcbaad8f304d02309af776312c9bf",
		                    "sha256": "bb1f9e108daa389e62b79067d1cdbef548f9934c9cc85a92565da7063cf36f89"
		                },
		                "online_reports": {
		                    "MISP_EVENT": "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/f83d06e6-aa2f-452e-a19d-59d40e874355.json",
		                    "MISP_CSV": "https://osint.digitalside.it/Threat-Intel/csv/f83d06e6-aa2f-452e-a19d-59d40e874355.csv",
		                    "OSINTDS_REPORT": "https://osint.digitalside.it/report/318323c9da34bf25833f7da32eab23d6.html",
		                    "STIX": "https://osint.digitalside.it/Threat-Intel/stix2/318323c9da34bf25833f7da32eab23d6.json",
		                    "STIXDETAILS": {
		                        "observed_time_frame": false,
		                        "indicators_count": {
		                            "hashes": 3,
		                            "urls": 1,
		                            "domains": 1,
		                            "ipv4": 0
		                        },
		                        "tlp": "white",
		                        "first_observed": "2023-07-06 23:51:01",
		                        "last_observed": "2023-07-06 23:51:01",
		                        "virus_total": {
		                            "vt_detection_ratio": "14/61",
		                            "vt_report": "https://www.virustotal.com/gui/file/bb1f9e108daa389e62b79067d1cdbef548f9934c9cc85a92565da7063cf36f89/detection"
		                        },
		                        "filename": "arm7",
		                        "filesize": 57148,
		                        "mime_type": "application/x-executable",
		                        "number_observed": 1
		                    }
		                }
		            },
		            {
		                "url": "h[REMOVED]p://monke.re/mips",
		                "hashes": {
		                    "md5": "579081f528d9279a87b298b9838c377b",
		                    "sha1": "45048073aad5997881dffe41e32f9b17beb1c2e1",
		                    "sha256": "8186a1d140631e6391978c08c35e01efb58963f65a86fddf7dec44eec7681c6b"
		                },
		                "online_reports": {
		                    "MISP_EVENT": "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/d01c2ad1-0e2c-4b26-9725-f8a86025bd75.json",
		                    "MISP_CSV": "https://osint.digitalside.it/Threat-Intel/csv/d01c2ad1-0e2c-4b26-9725-f8a86025bd75.csv",
		                    "OSINTDS_REPORT": "https://osint.digitalside.it/report/579081f528d9279a87b298b9838c377b.html",
		                    "STIX": "https://osint.digitalside.it/Threat-Intel/stix2/579081f528d9279a87b298b9838c377b.json",
		                    "STIXDETAILS": {
		                        "observed_time_frame": false,
		                        "indicators_count": {
		                            "hashes": 3,
		                            "urls": 1,
		                            "domains": 1,
		                            "ipv4": 0
		                        },
		                        "tlp": "white",
		                        "first_observed": "2023-07-07 00:31:02",
		                        "last_observed": "2023-07-07 00:31:02",
		                        "virus_total": {
		                            "vt_detection_ratio": "12/61",
		                            "vt_report": "https://www.virustotal.com/gui/file/8186a1d140631e6391978c08c35e01efb58963f65a86fddf7dec44eec7681c6b/detection"
		                        },
		                        "filename": "mips",
		                        "filesize": 48272,
		                        "mime_type": "application/x-executable",
		                        "number_observed": 1
		                    }
		                }
		            }
		        ]
		    }
		],
		"statistics": {
		    "itemsFound": 1,
		    "itemsSubmitted": 1
		},
		"list": {
		    "file": "latestdomains.txt",
		    "date": "2023-07-07 08:03:07+02:00",
		    "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestdomains.txt"
		}
	    },
	    "hash": {
		"items": [
		    {
		        "item": "7cb796c875cccc9233d82854a4e2fdf0",
		        "response": true,
		        "response_text": "Item found in latesthashes.json list",
		        "hashes": {
		            "md5": "7cb796c875cccc9233d82854a4e2fdf0",
		            "sha1": "158514acfa87d0b99e2af07a28004480bbf66e83",
		            "sha256": "49e64d72d5ed4fb7967da4b6851d94cdceffe4ba0316587767a13901fe580239"
		        },
		        "online_reports": {
		            "MISP_EVENT": "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/d6146389-4294-4a41-b4ca-6e74c74b7f8b.json",
		            "MISP_CSV": "https://osint.digitalside.it/Threat-Intel/csv/d6146389-4294-4a41-b4ca-6e74c74b7f8b.csv",
		            "OSINTDS_REPORT": "https://osint.digitalside.it/report/7cb796c875cccc9233d82854a4e2fdf0.html",
		            "STIX": "https://osint.digitalside.it/Threat-Intel/stix2/7cb796c875cccc9233d82854a4e2fdf0.json",
		            "STIXDETAILS": {
		                "observed_time_frame": false,
		                "indicators_count": {
		                    "hashes": 3,
		                    "urls": 1,
		                    "domains": 0,
		                    "ipv4": 1
		                },
		                "tlp": "white",
		                "first_observed": "2023-07-04 09:33:03",
		                "last_observed": "2023-07-04 09:33:03",
		                "virus_total": {
		                    "vt_detection_ratio": "32/71",
		                    "vt_report": "https://www.virustotal.com/gui/file/49e64d72d5ed4fb7967da4b6851d94cdceffe4ba0316587767a13901fe580239/detection"
		                },
		                "filename": "plugmanzx.exe",
		                "filesize": 924672,
		                "mime_type": "application/x-dosexec",
		                "number_observed": 1
		            }
		        },
		        "related_urls": [
		            "h[REMOVED]p://185.246.220.60/plugmanzx.exe"
		        ]
		    }
		],
		"statistics": {
		    "itemsFound": 1,
		    "itemsSubmitted": 1
		},
		"list": {
		    "file": "latesthashes.json",
		    "date": "2023-07-07 08:03:29+02:00",
		    "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latesthashes.json"
		}
	    },
	    "generalstatistics": {
		"url": 0,
		"ip": 0,
		"domain": 1,
		"hash": 1,
		"invalid": 0,
		"duplicates": 0,
		"itemsFound": 2,
		"itemsSubmitted": 2,
		"urlfound": 0,
		"ipfound": 0,
		"domainfound": 1,
		"hashfound": 1
	    },
	    "apiosintDSversion": "apiosintDS v.2.0.3"
	}	
