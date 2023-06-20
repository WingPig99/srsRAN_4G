/**
 *
 */

#ifndef SRSRAN_PDCP_PCAP_H
#define SRSRAN_PDCP_PCAP_H

#include "srsran/common/pcap.h"
#include "srsran/srslog/srslog.h"
#include "srsran/srsran.h"
#include <mutex>
#include <string>

namespace srsran {

class pdcp_pcap
{
public:
  pdcp_pcap();
  ~pdcp_pcap();
  pdcp_pcap(const pdcp_pcap& other)            = delete;
  pdcp_pcap& operator=(const pdcp_pcap& other) = delete;
  pdcp_pcap(pdcp_pcap&& other)                 = delete;
  pdcp_pcap& operator=(pdcp_pcap&& other)      = delete;

  void     enable();
  uint32_t open(std::string filename_);
  uint32_t close();
  void     write_ul_pdcp(uint16_t rnti, uint32_t eps_bearer_id, int32_t sn, uint8_t* pdu, uint32_t pdu_len_bytes);
  void     write_dl_pdcp(uint16_t rnti, uint32_t eps_bearer_id, int32_t sn, uint8_t* pdu, uint32_t pdu_len_bytes);

protected:
  std::mutex            mutex;
  srslog::basic_logger& logger;

private:
  bool        enable_write = false;
  std::string filename;
  FILE*       pcap_file            = nullptr;
  int         emergency_handler_id = -1;
};

} // namespace srsran

#endif // SRSRAN_PDCP_PCAP_H
