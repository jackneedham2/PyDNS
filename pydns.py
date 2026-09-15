"""
This is a very basic CLI for the DNS querier
It prints A records nicely, otherwise it just gives you the dict printed with pprint.
"""

import click
import dns_querier as querier
import pprint

@click.command()
@click.argument('domain')
@click.argument('ip')
@click.argument('qtype', required=False, default='A')

def do_query(domain, ip, qtype):
    response = querier.send_query(domain, ip, qtype=qtype)
    if response["QType"] == "A":
        print_answer(response)
    else:
        pprint.pp(response)


def print_answer(d):
    lines = []
    lines.append("\n")

    lines.append("RESPONSE")
    lines.append("=" * 12)  

    for k,v in d.items():
        if k == "Flags":
            for k2, v2 in d['Flags'].items():
                lines.append(" "*4 + f"{k2:<8}: {v2}")
        elif k == "Answers":
            pass
        else:
            lines.append(" "*2 + f"{k:<20}: {v}")


    lines.append("\n")

    lines.append("ANSWERS:")
    lines.append("=" * 12)  


    header = f"  {'#':<3} {'Domain':<12} {'Type':<5} {'Class':<6} {'TTL':<5} {'Data Length':<12} {'Data'}"
    lines.append(header)
    for i, ans in enumerate(d['Answers'], 1):
        lines.append(
            f"  {i:<3} {ans['Domain']:<12} {ans['Type']:<5} {ans['Class']:<6} "
            f"{ans['TTL']:<5} {ans['Data Length']:<12} {ans['Data']}"
        )
    lines.append("\n")
    print("\n".join(lines))


if __name__ == '__main__':
    do_query()