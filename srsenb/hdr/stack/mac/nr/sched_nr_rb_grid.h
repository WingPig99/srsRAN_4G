/**
 * Copyright 2013-2021 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#ifndef SRSRAN_SCHED_NR_RB_GRID_H
#define SRSRAN_SCHED_NR_RB_GRID_H

#include "../sched_common.h"
#include "lib/include/srsran/adt/circular_array.h"
#include "sched_nr_interface.h"
#include "sched_nr_pdcch.h"
#include "sched_nr_ue.h"

namespace srsenb {
namespace sched_nr_impl {

using pdsch_bitmap = srsran::bounded_bitset<25, true>;
using pusch_bitmap = srsran::bounded_bitset<25, true>;

using pdsch_t      = sched_nr_interface::pdsch_t;
using pdsch_list_t = sched_nr_interface::pdsch_list_t;

using pusch_list = sched_nr_interface::pusch_list;

struct pucch_t {};

const static size_t MAX_CORESET_PER_BWP = 3;
using slot_coreset_list                 = srsran::bounded_vector<coreset_region, MAX_CORESET_PER_BWP>;

struct bwp_slot_grid {
  pdcch_dl_list_t                                          pdcch_dl_list;
  pdcch_ul_list_t                                          pdcch_ul_list;
  slot_coreset_list                                        coresets;
  pdsch_bitmap                                             dl_rbgs;
  pdsch_list_t                                             pdsch_grants;
  pusch_bitmap                                             ul_rbgs;
  pusch_list                                               pusch_grants;
  srsran::bounded_vector<pucch_t, SCHED_NR_MAX_PDSCH_DATA> pucch_grants;

  bwp_slot_grid() = default;
  explicit bwp_slot_grid(const sched_cell_params& cell_params, uint32_t bwp_id_, uint32_t slot_idx_);
  void reset();
};

struct bwp_res_grid {
  bwp_res_grid(const sched_cell_params& cell_cfg_, uint32_t bwp_id_);

  bwp_slot_grid&       operator[](tti_point tti) { return slots[tti.sf_idx()]; };
  const bwp_slot_grid& operator[](tti_point tti) const { return slots[tti.sf_idx()]; };
  uint32_t             id() const { return bwp_id; }
  uint32_t             nof_prbs() const { return cell_cfg->cell_cfg.nof_prb; }

private:
  uint32_t                 bwp_id;
  const sched_cell_params* cell_cfg = nullptr;

  srsran::bounded_vector<bwp_slot_grid, TTIMOD_SZ> slots;
};

struct cell_res_grid {
  const sched_cell_params*                                        cell_cfg = nullptr;
  srsran::bounded_vector<bwp_res_grid, SCHED_NR_MAX_BWP_PER_CELL> bwps;

  explicit cell_res_grid(const sched_cell_params& cell_cfg);
};

class slot_bwp_sched
{
public:
  explicit slot_bwp_sched(uint32_t bwp_id, cell_res_grid& phy_grid_);

  alloc_result alloc_pdsch(slot_ue& ue, const rbgmask_t& dl_mask);
  alloc_result alloc_pusch(slot_ue& ue, const rbgmask_t& dl_mask);

  const sched_cell_params& cfg;

private:
  srslog::basic_logger& logger;
  bwp_res_grid&         bwp_grid;

  tti_point tti_rx;
};

} // namespace sched_nr_impl
} // namespace srsenb

#endif // SRSRAN_SCHED_NR_RB_GRID_H