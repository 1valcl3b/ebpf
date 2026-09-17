#include <core.p4>
#include <v1model.p4>


// =============================================================
// TIPOS
// =============================================================

typedef bit<48> MacAddress;
typedef bit<9> PortId;


// =============================================================
// CONSTANTES
// =============================================================

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IPPROTO_UDP    = 17;
const bit<16> DEST_PORT      = 5004;

// 10.0.0.2
const bit<32> DEST_IP        = 0x0A000002;


// =============================================================
// HEADERS
// =============================================================

header ethernet_t {
    MacAddress dstAddr;
    MacAddress srcAddr;
    bit<16> etherType;
}


header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}


header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}


header rtp_t {
    bit<2> version;
    bit<1> padding;
    bit<1> extension;
    bit<4> csrcCount;

    bit<1> marker;
    bit<7> payloadType;

    bit<16> sequenceNumber;
    bit<32> timestamp;
    bit<32> ssrc;
}


header h264_t {
    bit<8> nalHeader;
}


header fua_t {
    bit<8> fuHeader;
}


// =============================================================
// STRUCT HEADERS
// =============================================================

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    rtp_t rtp;
    h264_t h264;
    fua_t fua;
}


// =============================================================
// METADADOS
// =============================================================

struct metadata {

    // Fluxo UDP/5004 destinado ao cliente
    bit<1> is_udp_5004;

    // RTP válido
    bit<1> is_rtp;

    // Pacote H.264
    bit<1> is_h264;

    // Tipo H.264:
    // 0 = IDR
    // 1 = Non-IDR
    bit<2> h264_type;

    // Decisão de encaminhamento
    bit<1> do_drop;
    bit<1> do_forward;
}


// =============================================================
// CONTADORES
// =============================================================

// Contadores gerais
counter(1, CounterType.packets) packets_received;
counter(1, CounterType.packets) packets_forwarded;
counter(1, CounterType.packets) packets_dropped;


// Pacotes UDP destinados à porta 5004
counter(1, CounterType.packets) udp_5004_received;


// Pacotes H.264
counter(1, CounterType.packets) h264_received;


// H.264 IDR
counter(1, CounterType.packets) idr_received;


// H.264 Non-IDR
counter(1, CounterType.packets) non_idr_received;


// UDP/5004 encaminhados
counter(1, CounterType.packets) udp_5004_forwarded;


// UDP/5004 descartados
counter(1, CounterType.packets) udp_5004_dropped;


// =============================================================
// PARSER
// =============================================================

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {

    state start {
        transition parse_ethernet;
    }


    // ---------------------------------------------------------
    // Ethernet
    // ---------------------------------------------------------

    state parse_ethernet {

        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType) {

            ETHERTYPE_IPV4: parse_ipv4;

            default: accept;
        }
    }


    // ---------------------------------------------------------
    // IPv4
    // ---------------------------------------------------------

    state parse_ipv4 {

        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {

            IPPROTO_UDP: parse_udp;

            default: accept;
        }
    }


    // ---------------------------------------------------------
    // UDP
    // ---------------------------------------------------------

    state parse_udp {

        packet.extract(hdr.udp);

        transition select(hdr.udp.dstPort) {

            DEST_PORT: parse_rtp;

            default: accept;
        }
    }


    // ---------------------------------------------------------
    // RTP
    // ---------------------------------------------------------

    state parse_rtp {

        packet.extract(hdr.rtp);

        transition select(hdr.rtp.version) {

            2: parse_h264;

            default: accept;
        }
    }


    // ---------------------------------------------------------
    // H.264
    // ---------------------------------------------------------

    state parse_h264 {

        packet.extract(hdr.h264);

        transition select(hdr.h264.nalHeader & 0x1F) {

            28: parse_fua;

            default: accept;
        }
    }


    // ---------------------------------------------------------
    // FU-A
    // ---------------------------------------------------------

    state parse_fua {

        packet.extract(hdr.fua);

        transition accept;
    }
}


// =============================================================
// CHECKSUM
// =============================================================

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {

    apply {
    }
}


// =============================================================
// INGRESS
// =============================================================

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {


    // ---------------------------------------------------------
    // DROP
    // ---------------------------------------------------------

    action drop() {

        meta.do_drop = 1;
    }


    // ---------------------------------------------------------
    // FORWARD
    // ---------------------------------------------------------

    action forward(PortId port) {

        meta.do_forward = 1;

        std_meta.egress_spec = port;
    }


    // ---------------------------------------------------------
    // FLOOD
    // ---------------------------------------------------------

    action flood() {

        meta.do_forward = 1;

        if (std_meta.ingress_port == 1) {

            std_meta.egress_spec = 2;

        } else {

            std_meta.egress_spec = 1;
        }
    }


    // ---------------------------------------------------------
    // TABELA MAC
    // ---------------------------------------------------------

    table mac_forward {

        key = {
            hdr.ethernet.dstAddr : exact;
        }

        actions = {
            forward;
            flood;
            drop;
            NoAction;
        }

        size = 1024;

        default_action = drop();
    }


    // =========================================================
    // APPLY
    // =========================================================

    apply {


        // -----------------------------------------------------
        // CONTADOR GERAL DE PACOTES RECEBIDOS
        // -----------------------------------------------------

        packets_received.count(0);


        // -----------------------------------------------------
        // IDENTIFICA UDP/5004 DO FLUXO PARA O CLIENTE
        // -----------------------------------------------------

        if (
            hdr.ipv4.isValid() &&
            hdr.ipv4.dstAddr == DEST_IP &&
            hdr.udp.isValid() &&
            hdr.udp.dstPort == DEST_PORT
        ) {

            meta.is_udp_5004 = 1;

            udp_5004_received.count(0);
        }


        // -----------------------------------------------------
        // IDENTIFICA RTP
        // -----------------------------------------------------

        if (
            meta.is_udp_5004 == 1 &&
            hdr.rtp.isValid() &&
            hdr.rtp.version == 2
        ) {

            meta.is_rtp = 1;
        }


        // -----------------------------------------------------
        // IDENTIFICA H.264
        // -----------------------------------------------------

        if (
            meta.is_rtp == 1 &&
            hdr.h264.isValid()
        ) {

            bit<8> nal_type;

            nal_type = hdr.h264.nalHeader & 0x1F;


            // -------------------------------------------------
            // NAL TYPE 5 = IDR
            // -------------------------------------------------

            if (nal_type == 5) {

                meta.is_h264 = 1;

                meta.h264_type = 0;

                h264_received.count(0);

                idr_received.count(0);
            }


            // -------------------------------------------------
            // NAL TYPE 1 = NON-IDR
            // -------------------------------------------------

            else if (nal_type == 1) {

                meta.is_h264 = 1;

                meta.h264_type = 1;

                h264_received.count(0);

                non_idr_received.count(0);
            }


            // -------------------------------------------------
            // NAL TYPE 28 = FU-A
            // -------------------------------------------------

            else if (nal_type == 28) {

                if (hdr.fua.isValid()) {

                    bit<8> original_nal_type;

                    original_nal_type =
                        hdr.fua.fuHeader & 0x1F;


                    // -----------------------------------------
                    // FU-A contendo IDR
                    // -----------------------------------------

                    if (original_nal_type == 5) {

                        meta.is_h264 = 1;

                        meta.h264_type = 0;

                        h264_received.count(0);

                        idr_received.count(0);
                    }


                    // -----------------------------------------
                    // FU-A contendo Non-IDR
                    // -----------------------------------------

                    else if (original_nal_type == 1) {

                        meta.is_h264 = 1;

                        meta.h264_type = 1;

                        h264_received.count(0);

                        non_idr_received.count(0);
                    }
                }
            }
        }


        // -----------------------------------------------------
        // ENCAMINHAMENTO
        // -----------------------------------------------------

        if (hdr.ethernet.isValid()) {

            mac_forward.apply();

        } else {

            drop();
        }


        // -----------------------------------------------------
        // CONTADOR DE PACOTES ENCAMINHADOS
        // -----------------------------------------------------

        if (meta.do_forward == 1) {

            packets_forwarded.count(0);


            if (meta.is_udp_5004 == 1) {

                udp_5004_forwarded.count(0);
            }
        }


        // -----------------------------------------------------
        // CONTADOR DE PACOTES DESCARTADOS
        // -----------------------------------------------------

        if (meta.do_drop == 1) {

            packets_dropped.count(0);


            if (meta.is_udp_5004 == 1) {

                udp_5004_dropped.count(0);
            }


            mark_to_drop(std_meta);
        }
    }
}


// =============================================================
// EGRESS
// =============================================================

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {

    apply {
    }
}


// =============================================================
// CHECKSUM
// =============================================================

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {

    apply {
    }
}


// =============================================================
// DEPARSER
// =============================================================

control MyDeparser(
    packet_out packet,
    in headers hdr
) {

    apply {

        packet.emit(hdr.ethernet);

        packet.emit(hdr.ipv4);

        packet.emit(hdr.udp);

        packet.emit(hdr.rtp);

        packet.emit(hdr.h264);

        packet.emit(hdr.fua);
    }
}


// =============================================================
// SWITCH
// =============================================================

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
