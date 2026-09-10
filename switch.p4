#include <core.p4>
#include <v1model.p4>

typedef bit<48> MacAddress;
typedef bit<9>  PortId;

/*************************************************************************
 **************  H E A D E R S  *******************************************
 *************************************************************************/

header ethernet_t {
    MacAddress dstAddr;
    MacAddress srcAddr;
    bit<16>    etherType;
}

struct headers {
    ethernet_t ethernet;
}

struct metadata {
    /* Metadados customizados */
}

/*************************************************************************
 **************  P A R S E R  ********************************************
 *************************************************************************/

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {
    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

/*************************************************************************
 **************  C H E C K S U M  V E R I F I C A T I O N  ***************
 *************************************************************************/

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply { }
}

/*************************************************************************
 ***************  I N G R E S S   P R O C E S S I N G  *******************
 *************************************************************************/

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {

    /*
     * Descarta o pacote.
     */
    action drop() {
        mark_to_drop(std_meta);
    }

    /*
     * Encaminha o pacote para uma porta específica.
     */
    action forward(PortId port) {
        std_meta.egress_spec = port;
    }

    /*
     * Encaminha um broadcast para a outra porta.
     *
     * Temos somente duas portas:
     *
     * port 1 -> server
     * port 2 -> client
     */
    action flood() {

        if (std_meta.ingress_port == 1) {
            std_meta.egress_spec = 2;

        } else if (std_meta.ingress_port == 2) {
            std_meta.egress_spec = 1;

        } else {
            mark_to_drop(std_meta);
        }
    }

    /*
     * Tabela de encaminhamento baseada no MAC de destino.
     */
    table mac_forward {

        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward;
            flood;
            drop;
            NoAction;
        }

        size = 1024;

        /*
         * Se não houver uma entrada correspondente,
         * o pacote é descartado.
         */
        default_action = drop();
    }

    apply {

        if (hdr.ethernet.isValid()) {
            mac_forward.apply();

        } else {
            drop();
        }
    }
}

/*************************************************************************
 ***************  E G R E S S   P R O C E S S I N G  *********************
 *************************************************************************/

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {
    apply { }
}

/*************************************************************************
 **************  C H E C K S U M  G E N E R A T I O N  *******************
 *************************************************************************/

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply { }
}

/*************************************************************************
 **************  D E P A R S E R  ****************************************
 *************************************************************************/

control MyDeparser(
    packet_out packet,
    in headers hdr
) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

/*************************************************************************
 **************  S W I T C H   I N S T A N T I A T I O N  ****************
 *************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;