from fuzzowski.fuzzers.ifuzzer import IFuzzer
from fuzzowski.mutants.spike import *
from fuzzowski import Session

"""
S7comm Siemens Fuzzing module
@Author: h0rac

"""
class S7comm(IFuzzer):
    name = 's7comm'
    
    @staticmethod
    def get_requests() -> List[callable]:
        return [S7comm.S7_setup, S7comm.S7_read]


    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
       
        s_initialize("COTP_request")
        with s_block("TPKT"):
            s_byte(0x3, name='version', fuzzable=False)
            s_byte(0x00, name='reserved', fuzzable=False)
            s_word(0x0016, name='tpkt_length', endian='>', fuzzable=False)
        with s_block("COTP_req"):
            s_byte(0x11, name='cotp_length', fuzzable=False)
            s_byte(0xe0, name='cotp_pdu_type', fuzzable=False)
            s_word(0x0000, name='cotp_dst_ref', endian='>', fuzzable=False)
            s_word(0x0001, name='cotp_src_ref', endian='>', fuzzable=False)
            s_byte(0x00, name='cotp_class', fuzzable=False)
            s_byte(0xc0, name='cotp_param_code_tpdu-size', fuzzable=False)
            s_byte(0x01, name='cotp_param_len_1', fuzzable=False)
            s_byte(0x0a, name='cotp_tpdu_size', fuzzable=False)
            s_byte(0xc1, name='cotp_param_code_src-tsap', fuzzable=False)
            s_byte(0x02, name='cotp_param_len_2', fuzzable=False)
            s_word(0x001, name='cotp_src_tsap', fuzzable=False)
            s_byte(0xc2, name='cotp_param_code_dst-tsap', fuzzable=False)
            s_byte(0x02, name='cotp_param_len_3', fuzzable=False)
            s_word(0x0101, name='cotp_dst_tsap', fuzzable=False)


        # ---------------- S7Communication_setup ------------------- #
        s_initialize("S7Communication_setup")
        with s_block("TPKT"):
            s_byte(0x3, name='version', fuzzable=False)
            s_byte(0x00, name='reserved', fuzzable=False)
            s_word(0x0019, name='tpkt_length', endian='>', fuzzable=False)
        with s_block("COTP"):
            s_byte(0x02, name='cotp_length', fuzzable=False)
            s_byte(0xf0, name='tpdu_type', fuzzable=False)
            s_byte(0x80, name='tpdu_number', fuzzable=False)
        with s_block("S7Communication"):
            with s_block("header"):
                s_byte(0x32, name="protocol_id", fuzzable=False)
                s_byte(0x1, name="rosctr_job", fuzzable=False)
                s_word(0x0000, name="redundancy_identification", endian='>', fuzzable=True)
                s_word(0x0000, name="pdu_ref", endian='>', fuzzable=False)
                s_word(0x0008, name="param_len", endian='>', fuzzable=False)
                s_word(0x0000, name="data_len", endian='>', fuzzable=False)
            with s_block("parameter"):
                s_byte(0xf0, name="function_setup", fuzzable=False)
                s_byte(0x00, name="s7_reserved", fuzzable=False)
                s_word(0x0001, name='max_amq_calling', endian='>', fuzzable=False)
                s_word(0x0001, name='max_amq_called', endian='>', fuzzable=False)
                s_word(0x01e0, name='s7_pdu_len', endian='>', fuzzable=False)
            
        # ---------------- S7Communication_read ------------------- #
        s_initialize("S7Communication_read")
        with s_block("TPKT"):
            s_byte(0x3, name='version', fuzzable=False)
            s_byte(0x00, name='reserved', fuzzable=False)
            s_word(0x001f, name='tpkt_length', endian='>', fuzzable=False)
        with s_block("COTP"):
            s_byte(0x02, name='copt_length', fuzzable=False)
            s_byte(0xf0, name='tpdu_type', fuzzable=False)
            s_byte(0x80, name='tpdu_number', fuzzable=False)
        with s_block("S7Communication"):
            with s_block("header"):
                s_byte(0x32, name="protocol_id", fuzzable=False)
                s_byte(0x1, name="rosctr_job", fuzzable=False)
                s_word(0x0000, name="redundancy_identification", endian='>', fuzzable=True)
                s_word(0x0100, name="pdu_ref", endian='>', fuzzable=False)
                s_word(0x000e, name="param_len", endian='>', fuzzable=False)
                s_word(0x0000, name="data_len", endian='>', fuzzable=False)
            with s_block("parameter"):
                s_byte(0x04, name="function_read", fuzzable=False)
                s_byte(0x01, name="item_count", fuzzable=False)
                s_byte(0x12, name="variable_specification", fuzzable=False)
                s_byte(0x0a, name="len_of_addr_specification", fuzzable=False)
                s_byte(0x10, name="syntax_id", fuzzable=False)
                s_byte(0x02, name="transport_size", fuzzable=False)
                s_word(0x0001, name="s7_length", endian='>', fuzzable=False)
                s_word(0x0001, name="db_number", endian='>', fuzzable=False)
                s_byte(0x84, name="area", fuzzable=False)
                s_dword(0x0000, name='address', endian='>', fuzzable=False)
        # ---------------- s7Communication_read ------------------- #
        
    @staticmethod
    def S7_setup(session: Session) -> None:
        session.connect(s_get('COTP_request'), s_get('S7Communication_setup'))

    def S7_read(session: Session) -> None:
        session.connect(s_get('COTP_request'), s_get('S7Communication_setup'))
        session.connect(s_get('S7Communication_setup'), s_get('S7Communication_read'))
