/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<5>  IPV4_OPTION_INT = 31;

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#define MAX_HOPS 20

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}


header INT_header_t {
    // TODO
    bit<16>   traceid;
    bit<1>    sink;               // 判断有没有到sink交换机  
    bit<7>    remaining_hop_cnt;  // 剩余跳数
    bit<24>   undefined;
}


header INT_report_header_t {
    bit<8>      swid;
    bit<8>      dataType; // 0 UDP 1 TCP
    bit<16>     traceid;
    bit<16>     dataSize;
    bit<32>     dataSrc;
    bit<32>     dataDst;
    bit<48>     timestamp;
    bit<16>     undefined;
}

struct metadata {
    /* empty */
    @field_list(1)
    bit<8>      swid;
    @field_list(1,2)
    bit<16>     traceid;
    @field_list(1,2,3)
    bit<48>     timestamp;
    @field_list(1,2,3,4)
    bit<8>      dataType; // 0 UDP 1 TCP
    @field_list(1,2,3,4,5)
    bit<16>     dataSize;
    @field_list(1,2,3,4,5,6)
    bit<32>     dataSrc;
    @field_list(1,2,3,4,5,6,7)
    bit<32>     dataDst;
}

struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    ipv4_option_t      ipv4_option;
    
    // INT headers
    INT_header_t       int_header;
    // INT report header
    INT_report_header_t int_report_header;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
            5             : accept;
            default       : parse_ipv4_option;
        }
    }

    state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option) {
            31: parse_INT;
            default: accept;
        }
    }

    state parse_INT {
        packet.extract(hdr.int_header);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action activate_INT() {
        hdr.ipv4_option.setValid();
        hdr.int_header.setValid();

        hdr.ipv4_option.option = 31;
        hdr.ipv4_option.copyFlag = 0;
        hdr.ipv4_option.optClass = 0;
        hdr.ipv4_option.optionLength = 4;

        hdr.int_header.remaining_hop_cnt = MAX_HOPS;
        hdr.int_header.sink = 0;
        // 初始化一个traceid
        hash(hdr.int_header.traceid,
            HashAlgorithm.crc16, 16w0,
            {standard_metadata.ingress_global_timestamp,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            hdr.ipv4.protocol},
            32w65536
        );

        hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    }

    action add_INT(bit<8> swid) {
        // TODO
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;

        meta.swid = swid;
        meta.traceid = hdr.int_header.traceid;
        meta.timestamp = standard_metadata.ingress_global_timestamp;
        meta.dataType = hdr.ipv4.protocol;
        meta.dataSize = hdr.ipv4.totalLen;
        meta.dataSrc = hdr.ipv4.srcAddr;
        meta.dataDst = hdr.ipv4.dstAddr;
    }

    action set_sink(){
        hdr.int_header.sink = 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table INT_tab {
        actions = {
            add_INT;
            NoAction;
        }
        default_action = NoAction();
    }

    table sink_config {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_sink;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();

            if ((hdr.ipv4_option.isValid()) && (hdr.ipv4_option.copyFlag == 1)){
                // copy packet in previous switches
            }
            else{
                if ((hdr.ipv4.protocol == 6) || (hdr.ipv4.protocol == 17)) {
                    // 6 表示 TCP
                    // 17 表示 UDP
                    if (!hdr.int_header.isValid()) {
                        activate_INT();
                    }
                    // 修改 INT metadata
                    if (hdr.int_header.remaining_hop_cnt == 0){
                        // TODO
                    }else{
                        INT_tab.apply();
                    }
                    sink_config.apply();

                    // 克隆一个 INT packet
                    // 这里要在几个交换机执行下述命令，将100映射为上报的网口，目前是和原数据包一起发向egress_spec
                    // simple_switch_CLI --thrift-port=9090 s1
                    // simple_switch_CLI --thrift-port=9091 s2
                    // simple_switch_CLI --thrift-port=9092 s3
                    // mirroring_add 100 3
                    // clone(CloneType.I2E, 100);
                    clone_preserving_field_list(CloneType.I2E, 100, 1);
                }
                else{
                    // ICMP包不做处理
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    action remove_sink_header() {
        hdr.ipv4.ihl = hdr.ipv4.ihl - 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 4;

        // remove INT data added in INT sink
        hdr.int_header.setInvalid();
        hdr.ipv4_option.setInvalid();
        hdr.int_report_header.setInvalid();
    }

    action change_report_header(ip4Addr_t collectorAddr, macAddr_t dstAddr) {
        // collector的ip
        hdr.ipv4.dstAddr = collectorAddr;
        // 下一个交换机的mac地址
        hdr.ethernet.dstAddr = dstAddr;
    }

    table direct_report {
        actions = {
            change_report_header;
            NoAction;
        }
        default_action = NoAction;
    }


    apply {

        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
            if (hdr.ipv4_option.optionLength==4){
                // normal packets arrive at sink switch
                if (hdr.int_header.isValid() && hdr.int_header.sink==1){
                    remove_sink_header();
                }
            }
        }
        // direct_copy.apply();
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
            direct_report.apply();

            hdr.ipv4_option.setValid();
            hdr.int_report_header.setValid();
            hdr.int_header.setInvalid();
            // 重新装填option
            hdr.ipv4_option.optionLength = 24;
            hdr.ipv4_option.option = 31;
            hdr.ipv4_option.copyFlag = 1;
            hdr.ipv4_option.optClass = 0;
            // 重新装填 INT
            hdr.int_report_header.swid = meta.swid;
            hdr.int_report_header.traceid = meta.traceid;
            hdr.int_report_header.timestamp = meta.timestamp;
            hdr.int_report_header.dataType = meta.dataType;
            hdr.int_report_header.dataSize = meta.dataSize;
            hdr.int_report_header.dataSrc = meta.dataSrc;
            hdr.int_report_header.dataDst = meta.dataDst;

            // totallen只算固定首部+option长度 20+24
            hdr.ipv4.protocol = 4;// IPv4
            hdr.ipv4.totalLen = (bit<16>)(20 + 24);
            // hdr.ipv4.totalLen / 4
            hdr.ipv4.ihl = 11;
            // 截断 ether(14 Bytes)+IPv4(20+24 Bytes) header = 58 bytes 之后的部分 (截断option之后的)
            truncate((bit<32>)hdr.ipv4.totalLen + 14);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_option);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_report_header);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
