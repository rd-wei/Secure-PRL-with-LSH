/**
 \file 		abysetintersection.h
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of ABYSetIntersection.
 */
#ifndef __PSI_
#define __PSI_

// #include "WaksmanPermutation.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <cassert>
#include <vector>
#include <chrono>

struct bin{
    uint32_t tid;
    uint32_t tag;
    uint32_t bin_number;
    uint32_t a1;
    uint32_t a2;
    std::vector<uint32_t> data;
};

enum linear_pass_type{
    fill_dim_forward = 0,
    fill_dim_backward = 1,
    oblivious_expand = 2
};

class Timer{
private:
    std::chrono::time_point<std::chrono::system_clock> m_Start;
    std::chrono::time_point<std::chrono::system_clock> m_End;
    bool                                               m_Running;
public:
    Timer();
    void start();
    void stop();
    double elapsedSeconds();
};

std::vector<std::string> split(const std::string & s, const std::string & by);
int find_communication(const std::string & s);

int32_t test_psi_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nbits, uint32_t nthreads, e_mt_gen_alg mt_alg, uint32_t seed, std::string fname);
uint32_t lsh(uint32_t interval, uint32_t input);
uint32_t noise(uint32_t mask, e_role role);

std::vector<bin> smooth_bins(const std::vector<bin>& in_bins);
void pad_bins(std::vector<bin>& bins, uint32_t mask, e_role role);
void permute(std::vector<bin>& bins);
void print_bins(const std::vector<bin>& bins, uint32_t interval);

std::vector<std::vector<uint32_t>> bins2vectors(const std::vector<bin>& bins);
std::vector<bin> vectors2bins(const std::vector<std::vector<uint32_t>> & vs);
std::vector<uint32_t> bin2vec(const bin & b);
bin vec2bin(const std::vector<uint32_t> &v);

std::vector<bin> share_bins(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc, e_role my_role, e_role share_role);
std::vector<bin> unshare_bins(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc);

std::vector<bin> shuffle_bins(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc);
std::vector<uint32_t> concat(const std::vector<uint32_t> & in_vec, uint32_t factor);
std::vector<uint32_t> expand_vector(const std::vector<uint32_t> & in);
std::vector<bin> sort_bins_tag_tid(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc);
std::vector<bin> sort_bins_tid_tag(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc);
void QuickSort(ABYParty* party, BooleanCircuit* bc, std::vector<bin>& in, std::vector<uint64_t>& by, int32_t from, int32_t to);
int32_t Partition(ABYParty* party, BooleanCircuit* bc, std::vector<bin>& in, std::vector<uint64_t>& by, int32_t from, int32_t to);
share ** BuildPartitionCircuit(std::vector<uint64_t> shared, int32_t from, int32_t to, BooleanCircuit* sortcirc);

std::vector<uint32_t> BuildShuffleCircuit(share** shr_in, std::vector<uint32_t> shr_sel_bits,
		uint32_t neles, uint32_t bitlen, BooleanCircuit* permcirc);

void Fill_dim(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role, bool forward);
// This is unused because it is unstable: need to debug it, but hard to debug

void Linear_pass(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role, linear_pass_type t);
void Fill_dim_forward_pass(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role);
void Fill_dim_backward_pass(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role);

void AlignTable(std::vector<bin> & S2, ABYParty * party, BooleanCircuit* bc, uint32_t max_bin_number);

uint32_t ncomparisons(const std::vector<bin> & T1, const std::vector<bin> & T2);
std::vector<uint32_t> intersect(const std::vector<bin> & T1, const std::vector<bin> & T2, ABYParty * party, BooleanCircuit * bc);

void Fwd_pass_naive(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role);

std::vector<bin> Oblivious_Expand(const std::vector<bin> & in, ABYParty * party, BooleanCircuit * bc, uint32_t tid);

#endif /* __PSI_ */
