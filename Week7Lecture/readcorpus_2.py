
#!/usr/bin/python

import json, sys, getopt, os

def usage():
    print("Usage: %s --file=[filename]" % sys.argv[0])
    sys.exit()

def parse_args(argv):
    file=''
    myopts, args = getopt.getopt(argv, "-f", ["file="])
    for o, a in myopts:
        if o in ('-f, --file') and len(a) > 0:
            file=a
        else:
            usage()
    return file

def get_urldata(file):
    corpus = open(file)
    urldata = json.load(corpus, encoding="latin1")
    corpus.close()
    return urldata

def calc_accuracy(urldata):
    bad_urls = [url for url in urldata if is_bad(url)]
    if urldata[0]["malicious_url"] == None:
        print("Malicious Urls: {}".format(len(bad_urls)))
        return

    malicious_urls = [url for url in urldata if url["malicious_url"] == 1]
    hits = [url for url in bad_urls if url["malicious_url"] == 1]
    false_positives = len(bad_urls) - len(hits)
    misses = len(malicious_urls) - len(hits)
    accuracy = (len(hits) * 1.0/len(malicious_urls)) - (false_positives * 1.0/len(urldata))
    print("Mal Urls         {}".format(len(malicious_urls)))
    print("Hits:            {}".format(len(hits)))
    print("Misses:          {}".format(misses))
    print("False Positives: {}".format(false_positives))
    print("Accuracy:        {:.2%}".format(accuracy))


def is_bad(url):
    """
    This function uses a negative policy. Each url is innocent until proven guilty
    """
    w = 1

    # Alexa Rank
    if url["alexa_rank"] == None:
        w -= 0.7

    # Domain Age
    age_bias = 540
    age_weight = (age_bias - int(url["domain_age_days"])) / 300
    w -= age_weight

    return w < 0.3

def write_results(results):
    r_string = '\n'.join(['{}, {}'.format(r[0], r[1]) for r in results])
    with open('results.txt', 'w') as f:
        f.write('url, malicious_bit\n')
        f.write(r_string)

def main(argv):
    file = parse_args(argv)
    urldata = get_urldata(file)
    calc_accuracy(urldata)
    results = [(url["url"], is_bad(url)) for url in urldata]
    write_results(results)

if __name__ == "__main__":
    main(sys.argv[1:])