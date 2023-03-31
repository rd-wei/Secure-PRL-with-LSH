/**
 \file 		sort_compare_shuffle.cpp
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

#include "psi.h"
#include "../../../abycore/sharing/sharing.h"
#include "WaksmanPermutation.h"

#include <math.h>
#include <unistd.h>
#include <set>
#include <cassert>
#include <chrono>
#include <time.h>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <fstream>
#include <regex>
#define PSI


int32_t test_psi_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t neles, uint32_t bitlen, uint32_t nbins, uint32_t nthreads, e_mt_gen_alg mt_alg, uint32_t seed) {
	bool measure_bytes = false;
	assert(bitlen <= 32);
	uint64_t mask = ((uint64_t) 1 << bitlen)-1;
	uint32_t *srv_set, *cli_set;
	srv_set = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	cli_set = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t rndval;

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
		mt_alg, 80000000);

	std::vector<Sharing*>& sharings = party->GetSharings();
	BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

	for (uint32_t i = 0; i < neles; i++) {
		do {
			rndval = rand() & mask;
		} while (std::find(srv_set, srv_set+neles, rndval) != srv_set+neles
				|| std::find(cli_set, cli_set+neles, rndval) != cli_set+neles);

		srv_set[i] = rndval ;
		cli_set[i] = rndval ;
	}
	if (role == CLIENT){
		std::cout << "client set:" << std::endl;
		for(int32_t i = 0; i < neles; i++) {
			std::cout << "v: " << cli_set[i] << " ";
		}
		std::cout << std::endl;
	}
	else{
		std::cout << "server set:" << std::endl;
		for(int32_t i = 0; i < neles; i++) {
			std::cout << "v: " << srv_set[i] << " ";
		}
		std::cout << std::endl;
	}

	share* cli_shr = bc->PutSIMDINGate(neles, cli_set, (uint32_t) 32, CLIENT);
	share* srv_shr = bc->PutSIMDINGate(neles, srv_set, (uint32_t) 32, SERVER);

	cli_shr = bc->PutOUTGate(cli_shr, ALL);
	srv_shr = bc->PutOUTGate(srv_shr, ALL);

	party->ExecCircuit();

	uint64_t* out;
	uint32_t tmpbitlen, tmpnvals;
	std::vector<uint32_t> cli_set_plaintext, srv_set_plaintext;
	
	cli_shr->get_clear_value_vec(&out, &tmpbitlen, &tmpnvals);

	for (int i = 0; i < tmpnvals; i++){
		cli_set_plaintext.push_back(out[i]);
	}

	srv_shr->get_clear_value_vec(&out, &tmpbitlen, &tmpnvals);

	for (int i = 0; i < tmpnvals; i++){
		srv_set_plaintext.push_back(out[i]);
	}

	std::vector<uint32_t> intersection;
	for (auto e1 : cli_set_plaintext){
		for (auto e2 : srv_set_plaintext){
			if (e1 == e2){
				intersection.push_back(e1);
			}
		}
	}

	std::sort(intersection.begin(), intersection.end());

	std::cout << "true intersection: "<< std::endl;

	uint32_t count = 0;
	for (auto e : intersection){
		std::cout << e << "\t";
		count ++;
		if (count == 5){
			std::cout << std::endl;
			count = 0;
		}
	}
	std::cout << std::endl;

	delete party;

	clock_t start, end;
	double cpu_time_used;

	start = clock();

	Timer main_timer = Timer();

	main_timer.start();

	std::ostringstream strCout;


	party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
		mt_alg, 80000000);
	sharings = party->GetSharings();
	bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

	std::cout << "resetted parties" << std::endl;

	// Blocking

	std::vector<bin> cli_bins(nbins);
	std::vector<bin> srv_bins(nbins);

	for (uint32_t i = 0; i < nbins; i++){
		cli_bins[i].tag = i;
		cli_bins[i].tid = 2;
		cli_bins[i].a1 = 1;
		cli_bins[i].a2 = 1;
		srv_bins[i].tag = i;
		srv_bins[i].tid = 1;
		srv_bins[i].a1 = 1;
		srv_bins[i].a2 = 1;
	}

	uint32_t interval = (mask - 1) / nbins + 1;

	for (uint32_t i = 0; i < neles; i++){
		cli_bins[lsh(interval, cli_set[i])].data.push_back(cli_set[i]);
		srv_bins[lsh(interval, srv_set[i])].data.push_back(srv_set[i]);
	}

	// Smoothing bins

	std::vector<bin> cli_smooth = smooth_bins(cli_bins);
	std::vector<bin> srv_smooth = smooth_bins(srv_bins);

	// Padding bins

	pad_bins(cli_smooth, mask, role);
	pad_bins(srv_smooth, mask, role); // bin_number was added


	// Permute bins

	permute(cli_smooth);
	permute(srv_smooth);

	// Secret sharing and Union

	std::cout << "Secret sharing and Union" << std::endl;

	std::vector<bin> shr_cli_bins = share_bins(cli_smooth, party, bc, role, CLIENT);
	std::vector<bin> shr_srv_bins = share_bins(srv_smooth, party, bc, role, SERVER);

	std::vector<bin> shr_all_bins;

	for (bin b : shr_cli_bins){
		shr_all_bins.push_back(b);
	}
	for (bin b : shr_srv_bins){
		shr_all_bins.push_back(b);
	}

	// Shuffle

	std::cout << "begin shuffling" << std::endl;

	std::vector<bin> shuffled_bins = shuffle_bins(shr_all_bins, party, bc);

	// Sort

	std::cout << "begin sorting" << std::endl;
	std::vector<bin> sorted_bins = sort_bins_tag_tid(shuffled_bins, party, bc);

	std::cout << "\nbegin forward pass:" << std::endl;

	Fill_dim_forward_pass(sorted_bins, party, bc, role);

	std::cout << "\nForward pass: " << std::endl;

	std::cout << "\nbegin backward pass:" << std::endl;

	Fill_dim_backward_pass(sorted_bins, party, bc, role);

	std::cout << "\nBackward pass" << std::endl;

	std::cout << "begin sorting" << std::endl;
	std::vector<bin> Tc = sort_bins_tid_tag(sorted_bins, party, bc);
	std::cout << "end sorting" << std::endl;

	uint32_t n1, n2;
	n1 = shr_srv_bins.size();
	n2 = shr_cli_bins.size();

	std::vector<bin> T1, T2;

	for (uint32_t i = 0; i < n1; i++){
		T1.push_back(Tc[i]);
	}
	for (uint32_t i = n1; i < Tc.size(); i++){
		T2.push_back(Tc[i]);
	}

	std::cout << "begin expand" << std::endl;

	std::vector<bin> T1Expanded, T2Expanded;
	T1Expanded = Oblivious_Expand(T1, party, bc, 1);
	T2Expanded = Oblivious_Expand(T2, party, bc, 2);

	std::cout << "expand2" << std::endl;

	Linear_pass(T1Expanded, party, bc, role, oblivious_expand);
	Linear_pass(T2Expanded, party, bc, role, oblivious_expand);

	std::cout << "Align Table" << std::endl;

	AlignTable(T2Expanded, party, bc, shr_cli_bins.size());

	std::cout << "Match" << std::endl;

	if (measure_bytes){
		std::streambuf * oldCoutStreamBuf = std::cout.rdbuf();
		cout.rdbuf(strCout.rdbuf());
	}

	uint32_t num_comparisons = ncomparisons(T1Expanded, T2Expanded);
	std::vector<uint32_t> match_result = intersect(T1Expanded, T2Expanded, party, bc);

	auto it = std::unique(match_result.begin(), match_result.end());

	match_result.resize(std::distance(match_result.begin(), it));

	std::sort(match_result.begin(), match_result.end());

	std::cout << "unique" << std::endl;

	count = 0;
	for (auto e : match_result){
		std::cout << e << "\t";
		count ++;
		if (count == 5){
			std::cout << std::endl;
			count = 0;
		}
	}

	std::cout << std::endl;

	main_timer.stop();

	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

	delete party;

	int communication = 0;
	if (measure_bytes){
		std::string coutput(strCout.str());
		int communication = find_communication(coutput);
	}


	std::cout << "total time: " << main_timer.elapsedSeconds() << " seconds, ";
	std::cout << "cpu time: " << cpu_time_used << " seconds" << std::endl; 

	std::ofstream outfile;
	outfile.open(std::to_string(role) + std::to_string(seed) + ".txt", std::ios::trunc);
	outfile << "total_time: " << main_timer.elapsedSeconds() << " seconds" << std::endl;
	outfile << "cpu_time: " << cpu_time_used << " seconds" << std::endl; 
	outfile << "number_comparison: " << num_comparisons << std::endl;
	if (measure_bytes){
		outfile << "communication: " << communication << std::endl;
	}
	outfile.close();

	return 0;
}

std::vector<bin> sort_bins_tag_tid(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc){
	std::vector<bin> out;
	for (bin e : in_bins){
		bin b;
		b.tag = e.tag;
		b.tid = e.tid;
		b.bin_number = e.bin_number;
		b.a1 = e.a1;
		b.a2 = e.a2;
		for (auto d : e.data){
			b.data.push_back(d);
		}
		out.push_back(b);
	}
	std::vector<uint64_t> by;
	for (uint32_t i = 0; i < out.size(); i++){
		by.push_back(out[i].tag);
		by[i] = by[i] << 32;
		by[i] += out[i].tid;
	}
	QuickSort(party, bc, out, by, 0, out.size() - 1);
	return out;
}

std::vector<bin> sort_bins_tid_tag(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc){
	std::vector<bin> out;
	for (bin e : in_bins){
		bin b;
		b.tag = e.tag;
		b.tid = e.tid;
		b.bin_number = e.bin_number;
		b.a1 = e.a1;
		b.a2 = e.a2;
		for (auto d : e.data){
			b.data.push_back(d);
		}
		out.push_back(b);
	}
	std::vector<uint64_t> by;
	for (uint32_t i = 0; i < out.size(); i++){
		by.push_back(out[i].tid);
		by[i] = by[i] << 32;
		by[i] += out[i].tag;
	}
	QuickSort(party, bc, out, by, 0, out.size() - 1);
	return out;
}

std::vector<bin> shuffle_bins(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc){
	uint32_t nbins = in_bins.size();
	share** shr_in = (share**) malloc(sizeof(share*) * nbins);
	share** shr_out = (share**) malloc(sizeof(share*) * nbins);
	std::vector<std::vector<uint32_t>> in_vectors = bins2vectors(in_bins);
	uint32_t neles = in_vectors[0].size();
	std::vector<std::vector<uint32_t>> out_vectors;
	uint32_t out_bitlen, out_neles, *out_array;

	uint32_t bitlen = 32 * neles;

	//Set input gates to the circuit
	std::vector<std::vector<uint32_t>> expanded;
	for (auto e : in_vectors){
		expanded.push_back(expand_vector(e));
	}
	for (uint32_t i = 0; i < nbins; i++) {
		shr_in[i] = bc->PutSharedSIMDINGate(bitlen, expanded[i].data(), 1);
	}

	//Get inputs for the selection bits of the swap gate in the waksman network
	uint32_t nswapgates = estimateGates(nbins);
	vector<uint32_t> selbits(nswapgates);
	for (uint32_t i = 0; i < nswapgates; i++) {
		selbits[i] = ((share*) bc->PutINGate((uint32_t) rand() % 2, 1, SERVER))->get_wire_id(0);
	}


	vector<uint32_t> out = BuildShuffleCircuit(shr_in, selbits, nbins, bitlen, bc);

	for(uint32_t i = 0; i < nbins; i++) {
		shr_out[i] = new boolshare(1, bc);
		shr_out[i]->set_wire_id(0, out[i]);
		shr_out[i] = bc->PutSharedOUTGate(shr_out[i]);
	}


	party->ExecCircuit();

	for (uint32_t i = 0; i < nbins; i++){
		shr_out[i]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
		std::vector<uint32_t> out_vector (out_array, out_array + out_neles);
		uint32_t factor = out_neles / neles;
		out_vector = concat(out_vector, factor);
		out_vectors.push_back(out_vector);
	}

	party->Reset();

	free(shr_in);
	free(shr_out);

	return vectors2bins(out_vectors);
}



std::vector<uint32_t> concat(const std::vector<uint32_t> & in_vec, uint32_t factor){
	std::vector<uint32_t> out_vec;
	for (uint32_t i = 0; i < in_vec.size(); i+=factor){
		uint32_t out_value = 0;
		for (uint32_t j = 0; j < factor && i + j < in_vec.size(); j++){
			out_value += in_vec[i + j] << j;
		}
		out_vec.push_back(out_value);
	}
	return out_vec;
}

std::vector<bin> unshare_bins(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc){
	uint32_t nbins = in_bins.size();
	share** shr_in = (share**) malloc(sizeof(share*) * nbins);
	share** shr_out = (share**) malloc(sizeof(share*) * nbins);
	std::vector<std::vector<uint32_t>> in_vectors = bins2vectors(in_bins);
	uint32_t neles = in_vectors[0].size();
	std::vector<std::vector<uint32_t>> out_vectors;
	uint32_t out_bitlen, out_neles, *out_array;
	for (uint32_t i = 0; i < nbins; i++){
		shr_in[i] = bc->PutSharedSIMDINGate(neles, in_vectors[i].data(), (uint32_t) 32);
		shr_out[i] = bc->PutOUTGate(shr_in[i], ALL);
	}

	party->ExecCircuit();
	
	for (uint32_t i = 0; i < nbins; i++){
		shr_out[i]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
		std::vector<uint32_t> out_vector (out_array, out_array + out_neles);
		out_vectors.push_back(out_vector);
	}

	party->Reset();

	free(shr_in);
	free(shr_out);

	return vectors2bins(out_vectors);
}

std::vector<bin> share_bins(const std::vector<bin> & in_bins, ABYParty * party, BooleanCircuit* bc, e_role my_role, e_role share_role){
	uint32_t nbins = in_bins.size();
	share** shr_in = (share**) malloc(sizeof(share*) * nbins);
	share** shr_out = (share**) malloc(sizeof(share*) * nbins);
	std::vector<std::vector<uint32_t>> in_vectors = bins2vectors(in_bins);
	uint32_t neles = in_vectors[0].size();
	std::vector<std::vector<uint32_t>> out_vectors;
	uint32_t out_bitlen, out_neles, *out_array;
	for (uint32_t i = 0; i < nbins; i++){
		if (my_role == share_role){
			shr_in[i] = bc->PutSIMDINGate(neles, in_vectors[i].data(), (uint32_t) 32, my_role);
		}else{
			shr_in[i] = bc->PutDummySIMDINGate(neles, (uint32_t) 32);
		}
		shr_out[i] = bc->PutSharedOUTGate(shr_in[i]);
	}

	party->ExecCircuit();
	
	for (uint32_t i = 0; i < nbins; i++){
		shr_out[i]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
		std::vector<uint32_t> out_vector (out_array, out_array + out_neles);
		out_vectors.push_back(out_vector);
	}

	party->Reset();

	free(shr_in);
	free(shr_out);

	return vectors2bins(out_vectors);
}

std::vector<std::vector<uint32_t>> bins2vectors(const std::vector<bin>& bins){
	std::vector<std::vector<uint32_t>> vs;
	for (uint32_t i = 0; i < bins.size(); i ++){
		vs.push_back(bin2vec(bins[i]));
	}
	return vs;
}

std::vector<bin> vectors2bins(const std::vector<std::vector<uint32_t>> & vs){
	std::vector<bin> bins;
	for (uint32_t i = 0; i < vs.size(); i ++){
		bins.push_back(vec2bin(vs[i]));
	}
	return bins;
}

std::vector<uint32_t> bin2vec(const bin &b){
	uint32_t data_size = b.data.size();
	std::vector<uint32_t> v;
	v.push_back(b.tid);
	v.push_back(b.tag);
	v.push_back(b.bin_number);
	v.push_back(b.a1);
	v.push_back(b.a2);
	for (uint32_t i = 0; i < data_size; i++){
		v.push_back(b.data[i]);
	}
	return v;
}

bin vec2bin(const std::vector<uint32_t> &v){
	bin b;
	b.tid = v[0];
	b.tag = v[1];
	b.bin_number = v[2];
	b.a1 = v[3];
	b.a2 = v[4];
	for (uint32_t i = 5; i < v.size(); i++){
		b.data.push_back(v[i]);
	}
	return b;
}

void print_bins(const std::vector<bin>& bins, uint32_t interval){
	for (uint32_t i = 0; i< bins.size(); i++){
		std::cout << "tid: " << bins[i].tid << "\ttag: " << bins[i].tag << "\ta1: " << bins[i].a1 << "\ta2:" << bins[i].a2 << std::endl;
		std::cout << "\t\tbin number: " << bins[i].bin_number;
		std::cout << "\tfrom " << interval * bins[i].tag << " to " << interval * bins[i].tag + interval - 1 << std::endl;
		std::cout << "\t\t";
		uint32_t counter = 0;
		for (uint32_t j = 0; j < bins[i].data.size(); j++){
			std::cout << "v: " << bins[i].data[j] << "\t";
			counter ++;
			if (counter == 5){
				counter = 0;
				std::cout << std::endl << "\t\t";
			}
		}
		std::cout << std::endl;
	}
}


void pad_bins(std::vector<bin>& bins, uint32_t mask, e_role role){
	uint32_t nbins = bins.size();
	uint32_t max_size = 0;
	for (uint32_t k = 0; k < nbins; k++){
		max_size = std::max(max_size, (uint32_t)bins[k].data.size());
	}
	for (uint32_t k = 0; k < nbins; k++){
		if (role == CLIENT){
			bins[k].tid = 2;
			bins[k].a1 = 1;
		}
		else{
			bins[k].tid = 1;
			bins[k].a1 = 0;
		}
		bins[k].a2 = 1;
		bins[k].bin_number = k;
		while ((uint32_t) bins[k].data.size() < max_size){
			bins[k].data.push_back(noise(mask, role));
		}
	}
	return;
}

void permute(std::vector<bin>& bins){
	// permute by tags
	uint32_t max_tag = bins.size() / 2;
	uint32_t begin = 0;
	uint32_t end = begin + 1;
	while (end <= bins.size()){
		while (end < bins.size() && bins[begin].tag == bins[end].tag){
			end ++;
		}

		std::vector<uint32_t> new_bin;
		for (uint32_t k = begin; k < end; k++){
			std::copy(bins[k].data.begin(), bins[k].data.end(), std::back_inserter(new_bin));
		}
		std::random_shuffle(new_bin.begin(), new_bin.end());

		uint32_t i = 0;
		for (uint32_t k = begin; k < end; k++){
			for (uint32_t j = 0; j < bins[k].data.size(); j++){
				bins[k].data[j] = new_bin[i];
				i++;
			}
		}

		begin = end;
		end = begin + 1;
	}
	return;
}

std::vector<bin> smooth_bins(const std::vector<bin>& in_bins){
	uint32_t nbins = in_bins.size();
	uint32_t neles = 0;
	for (uint32_t k = 0; k < nbins; k++){
		neles += in_bins[k].data.size();
	}

	std::vector<bin> out_bins(in_bins.size() * 2);
	
	for (uint32_t k = 0; k < nbins * 2; k++){
		out_bins[k].tag = nbins; 
		out_bins[k].tid = 0;
		out_bins[k].a1 = 1;
		out_bins[k].a2 = 1;
	}

	uint32_t i = 0;
	uint32_t section = 0;
	uint32_t bin_size = neles / nbins;
	uint32_t j = 0;

	while (i < nbins){
		uint32_t start = section * bin_size;
		uint32_t end = std::min(start + bin_size, (uint32_t)in_bins[i].data.size());
		for (int k = start; k < end; k++){
			out_bins[j].data.push_back(in_bins[i].data[k]);
		}
		out_bins[j].tag = in_bins[i].tag;
		out_bins[j].tid = in_bins[i].tid;
		j ++;
		if (end == (uint32_t)in_bins[i].data.size()){
			i ++;
			section = 0;
		}else{
			section ++;
		}
	}

	return out_bins;
}

uint32_t lsh(uint32_t interval, uint32_t input){
	return input / interval;
}

uint32_t noise(uint32_t mask, e_role role){
	// if (tag == empty_code){
	// 	if (role == SERVER){
	// 		return tag * interval + 1;
	// 	}
	// 	else{
	// 		return tag * interval + 2;
	// 	}
	// }
	// uint32_t res = rand() % interval + tag * interval;
	// return res;
	if (role == SERVER){
		return mask + 1;
	}
	else{
		return mask + 2;
	}
}

std::vector<uint32_t> BuildShuffleCircuit(share** shr_in, vector<uint32_t> shr_sel_bits,
		uint32_t neles, uint32_t bitlen, BooleanCircuit* permcirc) {

	uint32_t seqsize = 2 * neles;
	std::vector<uint32_t> duptemppos((seqsize - 1) / 2);


	std::vector<std::vector<uint32_t> > temp(seqsize / 2);
	std::vector<std::vector<uint32_t> > tempvec(seqsize / 2);
	std::vector<std::vector<uint32_t> > dupvec(3);
	std::vector<std::vector<uint32_t> > tempbits(seqsize);
	std::vector<uint32_t> duptempvec;
	std::vector<uint32_t> duptempin((seqsize - 1) / 2);
	std::vector<uint32_t> a;
	std::vector<uint32_t> out(seqsize / 2);
	
	for (uint32_t i = 0; i < seqsize / 2; i++) {
		temp[i].push_back(shr_in[i]->get_wire_id(0));
	}
	//Build the swap gates for the waksman network
	PermutationNetwork* perm = new PermutationNetwork(seqsize / 2, permcirc);
	//Set the swap program of the gates
	perm->setPermutationGates(shr_sel_bits);
	//construct the actual Waksman permutation circuit
	for (uint32_t i = 0; i < seqsize / 2; i++) {
		tempvec[i].resize(1);
		tempvec[i][0] = permcirc->PutCombinerGate(temp[i]);
	}

	tempvec = perm->buildPermutationCircuit(tempvec);

	for (uint32_t i = 0; i < tempvec.size(); i++)
		out[i] = tempvec[i][0];


	return out;
}

void QuickSort(ABYParty* party, BooleanCircuit* bc, std::vector<bin>& in, std::vector<uint64_t>& by, int32_t from, int32_t to){
	// qsort in[from] to [to]
	if (from >= to){
		return;
	}
	int32_t p = Partition(party, bc, in, by, from, to);
	QuickSort(party, bc, in, by, from, p - 1);
	QuickSort(party, bc, in, by, p + 1, to);
}

int32_t Partition(ABYParty* party, BooleanCircuit* bc, std::vector<bin>& in, std::vector<uint64_t>& by, int32_t from, int32_t to){
	int32_t m = to - from + 1;
	int32_t i = from;
	share ** out = BuildPartitionCircuit(by, from, to, bc);
	party->ExecCircuit();
	for (int32_t j = 0; j < m - 1; j ++){
		uint64_t comp = out[j]->get_clear_value<uint32_t>();
		if (comp == 0) {
			std::swap(in[i], in[from + j]);
			std::swap(by[i], by[from + j]);
			i ++;
		}
	}
	party->Reset();
	std::swap(in[i], in[to]);
	std::swap(by[i], by[to]);
	free(out);
	return i;
}

share ** BuildPartitionCircuit(vector<uint64_t> shared, int32_t from, int32_t to, BooleanCircuit* sortcirc){
	int32_t m = to - from + 1;
	share ** in = (share**) malloc(sizeof(share*) * m);
	share ** out = (share**) malloc(sizeof(share*) * (m - 1));
	for (int32_t i = 0; i < m; i++){
		in[i] = sortcirc->PutSharedINGate(shared[from + i], (uint32_t) 64);
	}
	for (int32_t j = 0; j < m - 1; j++){
		out[j] = sortcirc->PutGTGate(in[j], in[m - 1]);
		out[j] = sortcirc->PutOUTGate(out[j], ALL);
	}
	free(in);
	return out;
}

std::vector<uint32_t> expand(uint32_t in){
	vector<uint32_t> out;
	for (uint32_t i = 0; i < 32; i++){
		out.push_back((in << (31 - i)) >> 31);
	}
	return out;
}

std::vector<uint32_t> expand_vector(const std::vector<uint32_t> & in){
	std::vector<uint32_t> out;
	for (uint32_t e : in){
		std::vector<uint32_t> r = expand(e);
		out.insert(out.end(), r.begin(), r.end());
	}
	return out;
}

share* putMaxGate(BooleanCircuit* bc, share* a, share* b){
	share * gt = bc->PutGTGate(a, b);
	return bc->PutMUXGate(a, b, gt);
}

std::pair<share*, share*> buildForwardPassCircuit(BooleanCircuit* bc, share* a1_inter1, share* a2_inter1, share* ya1, share* ya2, share* tag_eq){
	share* a1, *a2;
	a1 = bc->PutMUXGate(a1_inter1, ya1, tag_eq);
	a2 = bc->PutMUXGate(a2_inter1, ya2, tag_eq);

	return std::pair(a1, a2);
}

std::pair<share*, share*> buildBackwardPassCircuit(BooleanCircuit* bc, share * maxa1, share* maxa2, share* ya1, share* ya2, share* tag_equal){
	share *a1, *a2;

	a1 = bc->PutMUXGate(maxa1, ya1, tag_equal);
	a2 = bc->PutMUXGate(maxa2, ya2, tag_equal);

	return std::pair(a1, a2);
}

void Fill_dim_forward_pass(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role){
    std::vector<share *> shr_a1(in.size()), shr_a2(in.size());
	share * one = bc->PutCONSGate(1, (uint32_t) 32);
	share * two = bc->PutCONSGate(2, (uint32_t) 32);
	for (uint32_t i = 0; i < in.size(); i++){
		share * tid = bc->PutSharedINGate(in[i].tid, (uint32_t) 32);
		shr_a1[i] = bc->PutEQGate(tid, one);
		shr_a2[i] = bc->PutEQGate(tid, two);
		shr_a1[i] = bc->PutSharedOUTGate(shr_a1[i]);
		shr_a2[i] = bc->PutSharedOUTGate(shr_a2[i]);
	}
	party->ExecCircuit();
	for (uint32_t i = 0; i < in.size(); i++){
		in[i].a1 = shr_a1[i]->get_clear_value<uint32_t>();
		in[i].a2 = shr_a2[i]->get_clear_value<uint32_t>();
	}
	party->Reset();
	Linear_pass(in, party, bc, role, fill_dim_forward);
	return;
}

void Fill_dim_backward_pass(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role){
	std::reverse(in.begin(), in.end());
	Linear_pass(in, party, bc, role, fill_dim_backward);
	std::reverse(in.begin(), in.end());
	return;
}

void Linear_pass(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role, linear_pass_type t){
	std::vector<std::pair<share*, share*>> out_shr(in.size());
	std::vector<share *> gt_a1s_shr(in.size()), gt_a2s_shr(in.size()), 
						tags_eq_shr(in.size()), tids_eq_shr(in.size()), tids_eq_1_shr(in.size()),
						max_a1s_shr(in.size()), max_a2s_shr(in.size()),
						sum_a1s_shr(in.size()), sum_a2s_shr(in.size()),
						inter_2_a1s_shr(in.size()), inter_2_a2s_shr(in.size()),
						inter_1_a1s_shr(in.size()), inter_1_a2s_shr(in.size());
	std::vector<uint32_t> gt_a1s(in.size()), gt_a2s(in.size()), 
						tags_eq(in.size()), tids_eq(in.size()), tids_eq_1(in.size()),
						max_a1s(in.size()), max_a2s(in.size()),
						sum_a1s(in.size()), sum_a2s(in.size()),
						inter_2_a1s(in.size()), inter_2_a2s(in.size()),
						inter_1_a1s(in.size()), inter_1_a2s(in.size());
	share *out_a1, *out_a2;
	std::vector<share*> tags, tids;

	
	uint32_t region_size = 1;
	for (uint32_t round = 0; region_size < in.size(); round ++){
		if (t == fill_dim_forward || t == fill_dim_backward){
			for (uint32_t i = 0; i < in.size(); i++){
				uint32_t region = i / region_size;
				if (region % 2 == 1){
					uint32_t x = region * region_size - 1;
					// std::cout << "computing the first round of " << x << " to " << i << std::endl;
					share* xtag, *ytag, *xtid, *ytid, *xa1, *ya1, *xa2, *ya2;
					xtag = bc->PutSharedINGate(in[x].tag, (uint32_t) 32);
					ytag = bc->PutSharedINGate(in[i].tag, (uint32_t) 32);
					xtid = bc->PutSharedINGate(in[x].tid, (uint32_t) 32);
					ytid = bc->PutSharedINGate(in[i].tid, (uint32_t) 32);
					xa1 = bc->PutSharedINGate(in[x].a1, (uint32_t) 32);
					xa2 = bc->PutSharedINGate(in[x].a2, (uint32_t) 32);
					ya1 = bc->PutSharedINGate(in[i].a1, (uint32_t) 32);
					ya2 = bc->PutSharedINGate(in[i].a2, (uint32_t) 32);
					gt_a1s_shr[i] = bc->PutGTGate(xa1, ya1);
					gt_a2s_shr[i] = bc->PutGTGate(xa2, ya2);
					tags_eq_shr[i] = bc->PutEQGate(xtag, ytag);
					tids_eq_shr[i] = bc->PutEQGate(xtid, ytid);
					tids_eq_1_shr[i] = bc->PutEQGate(xtid, bc->PutCONSGate(1,(uint32_t) 32));
					gt_a1s_shr[i] = bc->PutSharedOUTGate(gt_a1s_shr[i]);
					gt_a2s_shr[i] = bc->PutSharedOUTGate(gt_a2s_shr[i]);
					tags_eq_shr[i] = bc->PutSharedOUTGate(tags_eq_shr[i]);
					tids_eq_shr[i] = bc->PutSharedOUTGate(tids_eq_shr[i]);
					tids_eq_1_shr[i] = bc->PutSharedOUTGate(tids_eq_1_shr[i]);

					sum_a1s_shr[i] = bc->PutADDGate(xa1, ya1);
					sum_a2s_shr[i] = bc->PutADDGate(xa2, ya2);
					sum_a1s_shr[i] = bc->PutSharedOUTGate(sum_a1s_shr[i]);
					sum_a2s_shr[i] = bc->PutSharedOUTGate(sum_a2s_shr[i]);
				}
			}
			party->ExecCircuit();
			for (uint32_t i = 0; i < in.size(); i++){
				if (i/region_size % 2 == 1){
					gt_a1s[i] = gt_a1s_shr[i]->get_clear_value<uint32_t>();
					gt_a2s[i] = gt_a2s_shr[i]->get_clear_value<uint32_t>();
					tags_eq[i] = tags_eq_shr[i]->get_clear_value<uint32_t>();
					tids_eq[i] = tids_eq_shr[i]->get_clear_value<uint32_t>();
					tids_eq_1[i] = tids_eq_1_shr[i]->get_clear_value<uint32_t>();
					sum_a1s[i] = sum_a1s_shr[i]->get_clear_value<uint32_t>();
					sum_a2s[i] = sum_a2s_shr[i]->get_clear_value<uint32_t>();
				}
			}
			party->Reset();

			for (uint32_t i = 0; i < in.size(); i++){
				uint32_t region = i / region_size;
				if (region % 2 == 1){
					uint32_t x = region * region_size - 1;
					// std::cout << "computing the maxes round of " << x << " to " << i << std::endl;
					share *xa1, *ya1, *xa2, *ya2, *gt_a1, *gt_a2;
					xa1 = bc->PutSharedINGate(in[x].a1, (uint32_t) 32);
					xa2 = bc->PutSharedINGate(in[x].a2, (uint32_t) 32);
					ya1 = bc->PutSharedINGate(in[i].a1, (uint32_t) 32);
					ya2 = bc->PutSharedINGate(in[i].a2, (uint32_t) 32);
					gt_a1 = bc->PutSharedINGate(gt_a1s[i], (uint32_t) 32);
					gt_a2 = bc->PutSharedINGate(gt_a2s[i], (uint32_t) 32);
					max_a1s_shr[i] = bc->PutMUXGate(xa1, ya1, gt_a1);
					max_a2s_shr[i] = bc->PutMUXGate(xa2, ya2, gt_a2);
					max_a1s_shr[i] = bc->PutSharedOUTGate(max_a1s_shr[i]);
					max_a2s_shr[i] = bc->PutSharedOUTGate(max_a2s_shr[i]);
				}
			}
			party->ExecCircuit();
			for (uint32_t i = 0; i < in.size(); i++){
				if (i/region_size % 2 == 1){
					max_a1s[i] = max_a1s_shr[i]->get_clear_value<uint32_t>();
					max_a2s[i] = max_a2s_shr[i]->get_clear_value<uint32_t>();
				}
			}
			party->Reset();
		}

		if (t == fill_dim_forward){
			for (uint32_t i = 0; i < in.size(); i++){
				uint32_t region = i / region_size;
				if (region % 2 == 1){
					uint32_t x = region * region_size - 1;
					// std::cout << "computing the inter2 round of " << x << " to " << i << std::endl;
					share * sum_a1, *sum_a2, *max_a1, *max_a2, *tid_eq_1;
					sum_a1 = bc->PutSharedINGate(sum_a1s[i], (uint32_t) 32);
					sum_a2 = bc->PutSharedINGate(sum_a2s[i], (uint32_t) 32);
					max_a1 = bc->PutSharedINGate(max_a1s[i], (uint32_t) 32);
					max_a2 = bc->PutSharedINGate(max_a2s[i], (uint32_t) 32);
					tid_eq_1 = bc->PutSharedINGate(tids_eq_1[i], (uint32_t) 32);
					
					inter_2_a1s_shr[i] = bc->PutMUXGate(sum_a1, max_a1, tid_eq_1);
					inter_2_a2s_shr[i] = bc->PutMUXGate(max_a2, sum_a2, tid_eq_1);

					inter_2_a1s_shr[i] = bc->PutSharedOUTGate(inter_2_a1s_shr[i]);
					inter_2_a2s_shr[i] = bc->PutSharedOUTGate(inter_2_a2s_shr[i]);
				}
			}
			party->ExecCircuit();
			for (uint32_t i = 0; i < in.size(); i++){
				if (i/region_size % 2 == 1){
					inter_2_a1s[i] = inter_2_a1s_shr[i]->get_clear_value<uint32_t>();
					inter_2_a2s[i] = inter_2_a2s_shr[i]->get_clear_value<uint32_t>();
				}
			}
			party->Reset();

			
			for (uint32_t i = 0; i < in.size(); i++){
				uint32_t region = i / region_size;
				if (region % 2 == 1){
					uint32_t x = region * region_size - 1;
					// std::cout << "computing the inter1 round of " << x << " to " << i << std::endl;
					share * inter_2_a1, *inter_2_a2, *sum_a1, *ya2, *tid_eq;
					inter_2_a1 = bc->PutSharedINGate(inter_2_a1s[i], (uint32_t) 32);
					inter_2_a2 = bc->PutSharedINGate(inter_2_a2s[i], (uint32_t) 32);
					sum_a1 = bc->PutSharedINGate(sum_a1s[i], (uint32_t) 32);
					ya2 = bc->PutSharedINGate(in[i].a2, (uint32_t) 32);
					tid_eq = bc->PutSharedINGate(tids_eq[i], (uint32_t) 32);
					
					inter_1_a1s_shr[i] = bc->PutMUXGate(inter_2_a1, sum_a1, tid_eq);
					inter_1_a2s_shr[i] = bc->PutMUXGate(inter_2_a2, ya2, tid_eq);

					inter_1_a1s_shr[i] = bc->PutSharedOUTGate(inter_1_a1s_shr[i]);
					inter_1_a2s_shr[i] = bc->PutSharedOUTGate(inter_1_a2s_shr[i]);
				}
			}
			party->ExecCircuit();
			for (uint32_t i = 0; i < in.size(); i++){
				if (i/region_size % 2 == 1){
					inter_1_a1s[i] = inter_1_a1s_shr[i]->get_clear_value<uint32_t>();
					inter_1_a2s[i] = inter_1_a2s_shr[i]->get_clear_value<uint32_t>();
				}
			}
			party->Reset();
		}
		share * zero;
		std::vector<std::vector<uint32_t>> vbins;
		std::vector<share *> shr_bins(in.size());
		if (t == oblivious_expand){
			zero = bc->PutCONSGate((uint64_t) 0, (uint32_t) 32);
			vbins = bins2vectors(in);
		}
		for (uint32_t i = 0; i < in.size(); i++){
			uint32_t region = i/region_size;
			if (region % 2 == 1){
				uint32_t x = region * region_size - 1;
				// std::cout << "comparing " << x << " to " << i << std::endl;
				share * a1_inter1, *a2_inter1, *ya1, *ya2, *max_a1, *max_a2, *tag_eq, *shr_binx, *shr_biny, *tid_eq_0;
				switch (t)
				{
				case fill_dim_forward:
					a1_inter1 = bc->PutSharedINGate(inter_1_a1s[i], (uint32_t) 32);
					a2_inter1 = bc->PutSharedINGate(inter_1_a2s[i], (uint32_t) 32);
					ya1 = bc->PutSharedINGate(in[i].a1, (uint32_t) 32);
					ya2 = bc->PutSharedINGate(in[i].a2, (uint32_t) 32);
					tag_eq = bc->PutSharedINGate(tags_eq[i], (uint32_t) 32);
					out_shr[i] = buildForwardPassCircuit(bc, a1_inter1, a2_inter1, ya1, ya2, tag_eq);
					out_a1 = bc->PutSharedOUTGate(out_shr[i].first);
					out_a2 = bc->PutSharedOUTGate(out_shr[i].second);
					out_shr[i] = std::pair(out_a1, out_a2);
					break;
				
				case fill_dim_backward:
					max_a1 = bc->PutSharedINGate(max_a1s[i], (uint32_t) 32);
					max_a2 = bc->PutSharedINGate(max_a2s[i], (uint32_t) 32);
					ya1 = bc->PutSharedINGate(in[i].a1, (uint32_t) 32);
					ya2 = bc->PutSharedINGate(in[i].a2, (uint32_t) 32);
					tag_eq = bc->PutSharedINGate(tags_eq[i], (uint32_t) 32);
					out_shr[i] = buildBackwardPassCircuit(bc, max_a1, max_a2, ya1, ya2, tag_eq);
					out_a1 = bc->PutSharedOUTGate(out_shr[i].first);
					out_a2 = bc->PutSharedOUTGate(out_shr[i].second);
					out_shr[i] = std::pair(out_a1, out_a2);
					break;
				
				case oblivious_expand:
					tid_eq_0 = bc->PutSharedINGate(in[i].tid, (uint32_t) 32);
					tid_eq_0 = bc->PutEQGate(tid_eq_0, zero);
					tid_eq_0 = bc->PutRepeaterGate(vbins[i].size(), tid_eq_0);
					
					shr_binx = bc->PutSharedSIMDINGate(vbins[x].size(), vbins[x].data(), (uint32_t) 32);
					shr_biny = bc->PutSharedSIMDINGate(vbins[i].size(), vbins[i].data(), (uint32_t) 32);

					shr_bins[i] = bc->PutMUXGate(shr_binx, shr_biny, tid_eq_0);
					shr_bins[i] = bc->PutSharedOUTGate(shr_bins[i]);
					break;

				default:
					break;
				}
			}
		}
		// std::cout << "b4 execution:"<<std::endl;
		party->ExecCircuit();
		// std::cout << "after execution:" << std::endl;
		if (t == fill_dim_forward || t == fill_dim_backward){
			for (uint32_t i = 0; i < in.size(); i++){
				if (i/region_size % 2 == 1){
					in[i].a1 = out_shr[i].first->get_clear_value<uint32_t>();
					in[i].a2 = out_shr[i].second->get_clear_value<uint32_t>();
				}
			}
		}
		
		uint32_t out_bitlen, out_neles, *out_array;
		if (t == oblivious_expand){
			for (uint32_t i = 0; i < in.size(); i++){
				if (i/region_size % 2 == 1){
					shr_bins[i]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
					std::vector<uint32_t> out_vector (out_array, out_array + out_neles);
					vbins[i] = out_vector;
				}
			}
			in = vectors2bins(vbins);
		}

		// std::cout << "b4 reset" << std::endl;
		party->Reset();
		region_size *= 2;
	}
	return;
}

void Fwd_pass_naive(std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, e_role role){
	share * shr_one = bc->PutCONSGate(1, (uint32_t) 32);
	shr_one = bc->PutSharedOUTGate(shr_one);
	party->ExecCircuit();
	for (bin b : in){
		b.a1 = shr_one->get_clear_value<uint32_t>();
		b.a2 = shr_one->get_clear_value<uint32_t>();
	}
	party->Reset();

	for (uint32_t i = 1; i < in.size(); i++){
		bin x = in[i-1];
		bin y = in[i];
		share * one = bc->PutCONSGate(1, (uint32_t) 32);
		share * xtag = bc->PutSharedINGate(x.tag, (uint32_t) 32);
		share * ytag = bc->PutSharedINGate(y.tag, (uint32_t) 32);
		share * xtid = bc->PutSharedINGate(x.tid, (uint32_t) 32);
		share * ytid = bc->PutSharedINGate(y.tid, (uint32_t) 32);
		share * xa1 = bc->PutSharedINGate(x.a1, (uint32_t) 32);
		share * xa2 = bc->PutSharedINGate(x.a2, (uint32_t) 32);

		share * tid_eq = bc->PutEQGate(xtid, ytid);
		share * tag_eq = bc->PutEQGate(xtag, ytag);
		share * both_eq = bc->PutANDGate(tid_eq, tag_eq);
		share * tid_eq_1 = bc->PutEQGate(xtid, one);

		share * a1_both_eq_1 = bc->PutADDGate(xa1, one);
		share * a1_both_eq_2 = xa1;
		share * a1_both_eq = bc->PutMUXGate(a1_both_eq_1, a1_both_eq_2, tid_eq_1);
		share * a1_tag_unequal = one;
		share * a1_only_tag_equal = xa1;
		share * a1_tag_equal = bc->PutMUXGate(a1_both_eq, a1_only_tag_equal, tid_eq);
		share * a1 = bc->PutMUXGate(a1_tag_equal, a1_tag_unequal, tag_eq);

		share * a2_both_eq_1 = xa2;
		share * a2_both_eq_2 = bc->PutADDGate(xa2, one);
		share * a2_both_eq = bc->PutMUXGate(a2_both_eq_1, a2_both_eq_2, tid_eq_1);
		share * a2_tag_unequal = one;
		share * a2_only_tag_equal = xa2;
		share * a2_tag_equal = bc->PutMUXGate(a2_both_eq, a2_only_tag_equal, tid_eq);
		share * a2 = bc->PutMUXGate(a2_tag_equal, a2_tag_unequal, tag_eq);

		share * a1_out = bc->PutSharedOUTGate(a1);
		share * a2_out = bc->PutSharedOUTGate(a2);

		party->ExecCircuit();

		y.a1 = a1_out->get_clear_value<uint32_t>();
		y.a2 = a2_out->get_clear_value<uint32_t>();
		
		party->Reset();
	}
}

std::vector<bin> Oblivious_Expand_old(const std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, std::vector<uint32_t> by){
	std::vector<share*> shr_ybin(in.size()), shr_yby(in.size()), shr_comp(in.size());
	std::vector<uint32_t> comp(in.size());
	std::vector<uint64_t> sums(in.size());
	std::vector<std::vector<uint32_t>> vbins;
	vbins = bins2vectors(in);

	share * fy, *ij, *geq, *geq_simd, *yby, *ypby, *ybin, *ypbin;

	uint32_t out_bitlen, out_neles, *out_array;

	Timer t;

	t.start();


	int j = pow(2, ceil(log(in.size())) - 1);

	while (j >= 1){

		for (int i = in.size() - j; i >= 1; i --){
			fy = bc->PutSharedINGate(by[i - 1], (uint32_t) 32);
			sums[i - 1] = i + j - 1;
			ij = bc->PutCONSGate(sums[i - 1], (uint32_t) 32);
			shr_comp[i - 1] = bc->PutGTGate(fy, ij); 
			shr_comp[i - 1] = bc->PutSharedOUTGate(shr_comp[i - 1]);
		}

		party->ExecCircuit();

		for (int i = in.size() - j; i >= 1; i --){
			comp[i - 1] = shr_comp[i - 1]->get_clear_value<uint32_t>();
		}

		party->Reset();

		for (int i = in.size() - j; i >= 1; i --){
			geq = bc->PutSharedINGate(comp[i - 1], (uint32_t) 32);
			yby = bc->PutSharedINGate(by[i - 1], (uint32_t) 32);
			ypby = bc->PutSharedINGate(by[i + j - 1], (uint32_t) 32);	
			
			shr_yby[i - 1] = bc->PutMUXGate(ypby, yby, geq);
			shr_yby[i + j - 1] = bc->PutMUXGate(yby, ypby, geq);

			shr_yby[i - 1] = bc->PutSharedOUTGate(shr_yby[i - 1]);
			shr_yby[i + j - 1] = bc->PutSharedOUTGate(shr_yby[i + j - 1]);

			party->ExecCircuit();
			by[i - 1] = shr_yby[i - 1]->get_clear_value<uint32_t>();
			by[i + j - 1] = shr_yby[i + j - 1] ->get_clear_value<uint32_t>();
			party->Reset();
		}

		
		for (int i = in.size() - j; i >= 1; i --){
			geq = bc->PutSharedINGate(comp[i - 1], (uint32_t) 32);
			geq_simd = bc->PutRepeaterGate(vbins[i - 1].size(), geq);
			ybin = bc->PutSharedSIMDINGate(vbins[i - 1].size(), vbins[i - 1].data(), (uint32_t) 32);
			ypbin = bc->PutSharedSIMDINGate(vbins[i + j - 1].size(), vbins[i + j - 1].data(), (uint32_t) 32);
			
			shr_ybin[i - 1] = bc->PutMUXGate(ypbin, ybin, geq_simd);
			shr_ybin[i + j - 1] = bc->PutMUXGate(ybin, ypbin, geq_simd);

			shr_ybin[i - 1] = bc->PutSharedOUTGate(shr_ybin[i - 1]);
			shr_ybin[i + j - 1] = bc->PutSharedOUTGate(shr_ybin[i + j - 1]);

			party->ExecCircuit();

			shr_ybin[i - 1]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
			std::vector<uint32_t> out_vector_i (out_array, out_array + out_neles);
			vbins[i - 1] = out_vector_i;
			shr_ybin[i + j - 1]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
			std::vector<uint32_t> out_vector_j (out_array, out_array + out_neles);
			vbins[i + j - 1] = out_vector_j;
			party->Reset();
		}

		j = j / 2;

		std::vector<bin> b = vectors2bins(vbins);
	}

	std::vector<bin> bins = vectors2bins(vbins);

	t.stop();
	std::cout << "Hopping: " << t.elapsedSeconds() << " seconds" << std::endl;


	return bins;
}

// does not work because of swapping with non-empty values.
std::vector<bin> Oblivious_Expand_new(const std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, std::vector<uint32_t> by){
	std::vector<share*> shr_ybin(in.size()), shr_yby(in.size()), shr_comp(in.size());
	std::vector<uint32_t> comp(in.size());
	std::vector<uint64_t> sums(in.size());
	std::vector<std::vector<uint32_t>> vbins;
	vbins = bins2vectors(in);

	std::vector<share *> fy(in.size()), ij(in.size()), geq(in.size()), yby(in.size()), ypby(in.size()), ybin(in.size()), ypbin(in.size()), geq_simd(in.size());

	uint32_t out_bitlen, out_neles, *out_array;

	Timer t;

	t.start();


	int j = pow(2, ceil(log(in.size())) - 1);

	while (j >= 1){

		for (int i = in.size() - j; i >= 1; i --){
			fy[i] = bc->PutSharedINGate(by[i - 1], (uint32_t) 32);
			sums[i - 1] = i + j - 1;
			ij[i] = bc->PutCONSGate(sums[i - 1], (uint32_t) 32);
			shr_comp[i - 1] = bc->PutGTGate(fy[i], ij[i]); 
			shr_comp[i - 1] = bc->PutSharedOUTGate(shr_comp[i - 1]);
		}

		party->ExecCircuit();

		for (int i = in.size() - j; i >= 1; i --){
			comp[i - 1] = shr_comp[i - 1]->get_clear_value<uint32_t>();
		}

		party->Reset();

		for (int i = in.size() - j; i >= 1; i --){
			geq[i] = bc->PutSharedINGate(comp[i - 1], (uint32_t) 32);
			yby[i] = bc->PutSharedINGate(by[i - 1], (uint32_t) 32);
			ypby[i] = bc->PutSharedINGate(by[i + j - 1], (uint32_t) 32);	
			
			shr_yby[i - 1] = bc->PutMUXGate(ypby[i], yby[i], geq[i]);
			shr_yby[i + j - 1] = bc->PutMUXGate(yby[i], ypby[i], geq[i]);

			shr_yby[i - 1] = bc->PutSharedOUTGate(shr_yby[i - 1]);
			shr_yby[i + j - 1] = bc->PutSharedOUTGate(shr_yby[i + j - 1]);
		}

		party->ExecCircuit();

		for (int i = in.size() - j; i >= 1; i --){
			by[i - 1] = shr_yby[i - 1]->get_clear_value<uint32_t>();
			by[i + j - 1] = shr_yby[i + j - 1] ->get_clear_value<uint32_t>();
		}
		
		party->Reset();

		
		for (int i = in.size() - j; i >= 1; i --){
			geq[i] = bc->PutSharedINGate(comp[i - 1], (uint32_t) 32);
			geq_simd[i] = bc->PutRepeaterGate(vbins[i - 1].size(), geq[i]);
			ybin[i] = bc->PutSharedSIMDINGate(vbins[i - 1].size(), vbins[i - 1].data(), (uint32_t) 32);
			ypbin[i] = bc->PutSharedSIMDINGate(vbins[i + j - 1].size(), vbins[i + j - 1].data(), (uint32_t) 32);
			
			shr_ybin[i - 1] = bc->PutMUXGate(ypbin[i], ybin[i], geq_simd[i]);
			shr_ybin[i + j - 1] = bc->PutMUXGate(ybin[i], ypbin[i], geq_simd[i]);

			shr_ybin[i - 1] = bc->PutSharedOUTGate(shr_ybin[i - 1]);
			shr_ybin[i + j - 1] = bc->PutSharedOUTGate(shr_ybin[i + j - 1]);
		}

		party->ExecCircuit();

		for (int i = in.size() - j; i >= 1; i --){

			shr_ybin[i - 1]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
			std::vector<uint32_t> out_vector_i (out_array, out_array + out_neles);
			vbins[i - 1] = out_vector_i;
			shr_ybin[i + j - 1]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
			std::vector<uint32_t> out_vector_j (out_array, out_array + out_neles);
			vbins[i + j - 1] = out_vector_j;
		}
			
		party->Reset();

		j = j / 2;

		std::vector<bin> b = vectors2bins(vbins);
	}

	std::vector<bin> bins = vectors2bins(vbins);

	t.stop();
	std::cout << "Hopping: " << t.elapsedSeconds() << " seconds" << std::endl;


	return bins;
}

std::vector<bin> Oblivious_Expand_array(const std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, std::vector<uint32_t> by){
	std::vector<uint32_t> pby(by.size());
	std::vector<share*> shr_ybin(in.size()),shr_ypbin(in.size()), shr_yby(in.size()), shr_ypby(in.size()), shr_comp(in.size());
	std::vector<uint32_t> comp(in.size());
	std::vector<uint64_t> sums(in.size());
	std::vector<std::vector<uint32_t>> vbins;
	vbins = bins2vectors(in);

	std::vector<share *> fy(in.size()), ij(in.size()), geq(in.size()), yby(in.size()), ypby(in.size()), ybin(in.size()), ypbin(in.size()), geq_simd(in.size());

	uint32_t out_bitlen, out_neles, *out_array;

	Timer t;

	t.start();

	std::vector<bin> empty_bins(in.size());

	for (uint32_t i = 0; i < in.size(); i++){
		bin b;
		b.tid = 0;
		b.tag = 0;
		b.bin_number = 0;
		b.a1 = 0;
		b.a2 = 0;
		while ((uint32_t) b.data.size() < in[0].data.size()){
			b.data.push_back(0);
		}
		empty_bins[i] = b;
	}

	std::vector<std::vector<uint32_t>> ebins;


	int j = pow(2, ceil(log(in.size())) - 1);
	int k = j;

	while (j >= 1){

		ebins = bins2vectors(empty_bins);
		for (uint32_t i = 0; i < by.size(); i++){
			pby[i] = 0;
		}

		for (int i = in.size() - j; i >= 1; i --){
			fy[i - 1] = bc->PutSharedINGate(by[i - 1], (uint32_t) 32);
			sums[i - 1] = i + j - 1;
			ij[i - 1] = bc->PutCONSGate(sums[i - 1], (uint32_t) 32);
			shr_comp[i - 1] = bc->PutGTGate(fy[i - 1], ij[i - 1]); 
			shr_comp[i - 1] = bc->PutSharedOUTGate(shr_comp[i - 1]);
		}

		party->ExecCircuit();

		for (int i = in.size() - j; i >= 1; i --){
			comp[i - 1] = shr_comp[i - 1]->get_clear_value<uint32_t>();
		}

		party->Reset();

		share * zero = bc->PutCONSGate(1, (uint32_t) 32);
		zero = bc->PutXORGate(zero, zero);

		for (int i = in.size() - j; i >= 1; i --){
			geq[i] = bc->PutSharedINGate(comp[i - 1], (uint32_t) 32);
			yby[i] = bc->PutSharedINGate(by[i - 1], (uint32_t) 32);
			ypby[i] = zero;
			
			shr_yby[i - 1] = bc->PutMUXGate(ypby[i], yby[i], geq[i]);
			shr_ypby[i + j - 1] = bc->PutMUXGate(yby[i], ypby[i], geq[i]);

			shr_yby[i - 1] = bc->PutSharedOUTGate(shr_yby[i - 1]);
			shr_ypby[i + j - 1] = bc->PutSharedOUTGate(shr_ypby[i + j - 1]);
		}

		party->ExecCircuit();

		for (int i = in.size() - j; i >= 1; i --){
			by[i - 1] = shr_yby[i - 1]->get_clear_value<uint32_t>();
			pby[i + j - 1] = shr_ypby[i + j - 1] ->get_clear_value<uint32_t>();
		}
		
		party->Reset();

		for (int i = 0; i <by.size(); i++){
			shr_yby[i] = bc->PutSharedINGate(by[i], (uint32_t) 32);
			shr_ypby[i] = bc->PutSharedINGate(pby[i], (uint32_t) 32);
			shr_yby[i] = bc->PutADDGate(shr_yby[i], shr_ypby[i]);
			shr_yby[i] = bc->PutSharedOUTGate(shr_yby[i]);
		}

		party->ExecCircuit();

		for (int i = 0; i <by.size(); i++){
			by[i] = shr_yby[i]->get_clear_value<uint32_t>();
		}

		party->Reset();

		
		for (int i = in.size() - j; i >= 1; i --){
			geq[i] = bc->PutSharedINGate(comp[i - 1], (uint32_t) 32);
			geq_simd[i] = bc->PutRepeaterGate(vbins[i - 1].size(), geq[i]);
			ybin[i] = bc->PutSharedSIMDINGate(vbins[i - 1].size(), vbins[i - 1].data(), (uint32_t) 32);
			ypbin[i] = bc->PutSharedSIMDINGate(ebins[i + j - 1].size(), ebins[i + j - 1].data(), (uint32_t) 32);
			
			shr_ybin[i - 1] = bc->PutMUXGate(ypbin[i], ybin[i], geq_simd[i]);
			shr_ypbin[i + j - 1] = bc->PutMUXGate(ybin[i], ypbin[i], geq_simd[i]);

			shr_ybin[i - 1] = bc->PutSharedOUTGate(shr_ybin[i - 1]);
			shr_ypbin[i + j - 1] = bc->PutSharedOUTGate(shr_ypbin[i + j - 1]);
		}

		party->ExecCircuit();

		for (int i = in.size() - j; i >= 1; i --){

			shr_ybin[i - 1]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
			std::vector<uint32_t> out_vector_i (out_array, out_array + out_neles);
			vbins[i - 1] = out_vector_i;
			shr_ypbin[i + j - 1]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
			std::vector<uint32_t> out_vector_j (out_array, out_array + out_neles);
			ebins[i + j - 1] = out_vector_j;
		}
			
		party->Reset();

		for (int i = 0; i < in.size(); i++){
			ybin[i] = bc->PutSharedSIMDINGate(vbins[i].size(), vbins[i].data(), (uint32_t) 32);
			ypbin[i] = bc->PutSharedSIMDINGate(ebins[i].size(), ebins[i].data(), (uint32_t) 32);

			shr_ybin[i] = bc->PutXORGate(ybin[i], ypbin[i]);
			shr_ybin[i] = bc->PutSharedOUTGate(shr_ybin[i]);
		}
		
		party->ExecCircuit();

		for (int i = 0; i < in.size(); i++){
			shr_ybin[i]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
			std::vector<uint32_t> out_vector_i (out_array, out_array + out_neles);
			vbins[i] = out_vector_i;
		}
			
		party->Reset();

		j = j / 2;
	}

	std::vector<bin> bins = vectors2bins(vbins);

	t.stop();
	std::cout << "Hopping: " << t.elapsedSeconds() << " seconds" << std::endl;


	return bins;
}

// select one of the methods
std::vector<bin> Oblivious_Expand(const std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, std::vector<uint32_t> by){
	return Oblivious_Expand_array(in, party, bc, by);
}

std::vector<bin> Oblivious_Expand(const std::vector<bin> & in, ABYParty * party, BooleanCircuit* bc, uint32_t tid){
	std::vector<uint32_t> by;
	std::vector<share*> out_shr(in.size());

	Timer t;

	t.start();
	
	for (bin b : in){
		if (tid == 1){
			by.push_back(b.a2);
		}
		else{
			by.push_back(b.a1);
		}
	}

	t.stop();
	std::cout << "Seperating bins: " << t.elapsedSeconds() << " seconds" << std::endl;
	t.start();

	ostringstream oss;
    auto cout_buff = std::cout.rdbuf(oss.rdbuf());

	
	uint32_t region_size = 1;
	for (uint32_t round = 0; region_size < in.size(); round ++){
		for (uint32_t i = 0; i < in.size(); i++){
			uint32_t region = i/region_size;
			if (region % 2 == 1){
				uint32_t x = region * region_size - 1;
				share* in_x = bc->PutSharedINGate(by[x], (uint32_t) 32);
				share* in_y = bc->PutSharedINGate(by[i], (uint32_t) 32);

				out_shr[i] = bc->PutADDGate(in_x, in_y);
				if (i == by.size() - 1){
					bc->PutPrintValueGate(out_shr[i], "Clear expanded size");
				}
				out_shr[i] = bc->PutSharedOUTGate(out_shr[i]);
			}
		}
		party->ExecCircuit();
		for (uint32_t i = 0; i < in.size(); i++){
			if (i/region_size % 2 == 1){
				by[i] = out_shr[i]->get_clear_value<uint32_t>();
			}
		}
		party->Reset();
		region_size *= 2;
	}
    cout.rdbuf(cout_buff);
    string capture_cout = oss.str();
	std::cout << "content captured{" << capture_cout << "}" << std::endl;

	std::cout << "get clear expanded size" << std::endl;

	uint32_t expanded_size, expanded_size_buffer;
	std::string token;
	std::istringstream in_stream(capture_cout);
	while (in_stream){
		in_stream >> token;
		std::istringstream token_stream(token);
		token_stream >> expanded_size_buffer;
		if (expanded_size_buffer){
			expanded_size = expanded_size_buffer;
		}
	}

	std::cout << "Expanded size: " << expanded_size << std::endl;

	std::vector<bin> A(expanded_size);
	for (int i = 0; i < in.size(); i++){
		A[i] = in[i];
	}
	for (uint32_t i = in.size(); i < expanded_size; i++){
		bin b;
		b.tid = 0;
		b.tag = 0;
		b.bin_number = 0;
		b.a1 = 0;
		b.a2 = 0;
		while ((uint32_t) b.data.size() < in[0].data.size()){
			b.data.push_back(0);
		}
		A[i] = b;
		by.push_back(0);
	}

	std::cout << "add one" << std::endl;

	std::vector<share*> shr_by(expanded_size);
	share* one = bc->PutCONSGate((uint64_t) 1, (uint32_t) 32);
	for (uint32_t i = 0; i < expanded_size; i++){
		if (i >= in.size()){
			shr_by[i] = bc->PutCONSGate((uint64_t) 0, (uint32_t) 32);
			continue;
		}
		if (i == 0){
			shr_by[i] = one;
			continue;
		}
		shr_by[i] = bc->PutSharedINGate(by[i - 1], (uint32_t) 32);
		shr_by[i] = bc->PutADDGate(shr_by[i], one);
	}
	for (uint32_t i = 0; i < expanded_size; i++){
		shr_by[i] = bc->PutSharedOUTGate(shr_by[i]);
	}
	party->ExecCircuit();
	for (uint32_t i = 0; i < expanded_size; i++){
		by[i] = shr_by[i]->get_clear_value<uint32_t>();\
	}
	party->Reset();

	t.stop();
	std::cout << "Calculating target position: " << t.elapsedSeconds() << " seconds" << std::endl;
	t.start();

	std::vector<std::vector<uint32_t>> vbins;
	std::vector<share*> shr_bins(A.size());
	vbins = bins2vectors(A);
	for (uint32_t i = 0; i < A.size(); i++){
		shr_bins[i] = bc->PutSharedSIMDINGate(vbins[i].size(), vbins[i].data(), (uint32_t) 32);
		shr_bins[i] = bc->PutSharedOUTGate(shr_bins[i]);
	}
	party->ExecCircuit();
	uint32_t out_bitlen, out_neles, *out_array;
	
	for (uint32_t i = 0; i < A.size(); i++){
		shr_bins[i]->get_clear_value_vec(&out_array, &out_bitlen, &out_neles);
		std::vector<uint32_t> out_vector (out_array, out_array + out_neles);
		vbins[i] = out_vector;
	}
	party->Reset();

	A = vectors2bins(vbins);

	t.stop();
	std::cout << "Secret sharing the bins: " << t.elapsedSeconds() << " seconds" << std::endl;
	t.start();

	return Oblivious_Expand(A, party, bc, by);
}

std::vector<uint32_t>calc_q(const std::vector<bin> & S2, ABYParty * party, BooleanCircuit* bc){
	std::vector<uint32_t> q(S2.size()), tag_eqs(S2.size()), sums(S2.size());
	std::vector<share*> shr_q(S2.size()), shr_tag_eqs(S2.size()), shr_sums(S2.size());
	for (int i = 0; i < S2.size(); i ++){
		shr_q[i] = bc->PutCONSGate(1, (uint32_t) 32);
		shr_q[i] = bc->PutSharedOUTGate(shr_q[i]);
	}
	party->ExecCircuit();
	for (int i = 0; i < S2.size(); i++){
		q[i] = shr_q[i]->get_clear_value<uint32_t>();
	}
	party->Reset();

	
	uint32_t region_size = 1;
	for (uint32_t round = 0; region_size < S2.size(); round ++){
		for (uint32_t i = 0; i < S2.size(); i++){
			uint32_t region = i/region_size;
			if (region % 2 == 1){
				uint32_t x = region * region_size - 1;

				share * tagx, * tagy, * qx, * qy;
				tagx = bc->PutSharedINGate(S2[x].tag, (uint32_t) 32);
				tagy = bc->PutSharedINGate(S2[i].tag, (uint32_t) 32);
				shr_tag_eqs[i] = bc->PutEQGate(tagx, tagy);
				qx = bc->PutSharedINGate(q[x], (uint32_t) 32);
				qy = bc->PutSharedINGate(q[i], (uint32_t) 32);
				shr_sums[i] = bc->PutADDGate(qx, qy);
				bc->PutPrintValueGate(shr_tag_eqs[i], "intermediate tag_eq[" + std::to_string(i) + "]");
				bc->PutPrintValueGate(shr_sums[i], "intermediate sum[" + std::to_string(i) + "]");

				shr_tag_eqs[i] = bc->PutSharedOUTGate(shr_tag_eqs[i]);
				shr_sums[i] = bc->PutSharedOUTGate(shr_sums[i]);
			}
		}
		party->ExecCircuit();
		for (uint32_t i = 0; i < S2.size(); i++){
			if (i/region_size % 2 == 1){
				tag_eqs[i] = shr_tag_eqs[i]->get_clear_value<uint32_t>();
				sums[i] = shr_sums[i]->get_clear_value<uint32_t>();
			}
		}
		party->Reset();

		for (uint32_t i = 0; i < S2.size(); i++){
			uint32_t region = i/region_size;
			if (region % 2 == 1){
				uint32_t x = region * region_size - 1;

				share * sum, * tag_eq, * qy;
				tag_eq = bc->PutSharedINGate(tag_eqs[i], (uint32_t) 32);
				qy = bc->PutSharedINGate(q[i], (uint32_t) 32);
				sum = bc->PutSharedINGate(sums[i], (uint32_t) 32);
				bc->PutPrintValueGate(qy, "input qy[" + std::to_string(i) + "]");
				bc->PutPrintValueGate(sum, "input sum[" + std::to_string(i) + "]");
				shr_q[i] = bc->PutMUXGate(sum, qy, tag_eq);
				bc->PutPrintValueGate(shr_q[i], "intermediate q[" + std::to_string(i) + "]");
				shr_q[i] = bc->PutSharedOUTGate(shr_q[i]);
			}
		}
		party->ExecCircuit();
		for (uint32_t i = 0; i < S2.size(); i++){
			if (i/region_size % 2 == 1){
				q[i] = shr_q[i]->get_clear_value<uint32_t>();
			}
		}
		party->Reset();
		region_size *= 2;
	}

	share* one = bc->PutCONSGate((uint64_t) 1, (uint32_t) 32);
	for (uint32_t i = 0; i < S2.size(); i++){
		shr_q[i] = bc->PutSharedINGate(q[i], (uint32_t) 32);
		shr_q[i] = bc->PutSUBGate(shr_q[i], one);
		bc->PutPrintValueGate(shr_q[i], "q[" + std::to_string(i) + "]");
		shr_q[i] = bc->PutSharedOUTGate(shr_q[i]);
	}
	party->ExecCircuit();
	for (uint32_t i = 0; i < S2.size(); i++){
		q[i] = shr_q[i]->get_clear_value<uint32_t>();
	}
	party->Reset();

	return q;
}

std::vector<uint32_t>calc_p(const std::vector<bin> & S2, ABYParty * party, BooleanCircuit* bc){

	std::vector<uint32_t> p(S2.size()), bin_number_eqs(S2.size()), sums(S2.size());
	std::vector<share*> shr_p(S2.size()), shr_bin_number_eqs(S2.size()), shr_sums(S2.size());
	for (int i = 0; i < S2.size(); i ++){
		shr_p[i] = bc->PutCONSGate(1, (uint32_t) 32);
		shr_p[i] = bc->PutSharedOUTGate(shr_p[i]);
	}
	party->ExecCircuit();
	for (int i = 0; i < S2.size(); i++){
		p[i] = shr_p[i]->get_clear_value<uint32_t>();
	}
	party->Reset();

	
	uint32_t region_size = 1;
	for (uint32_t round = 0; region_size < S2.size(); round ++){
		for (uint32_t i = 0; i < S2.size(); i++){
			uint32_t region = i/region_size;
			if (region % 2 == 1){
				uint32_t x = region * region_size - 1;

				share * bin_n_x, * bin_n_y, * px, * py;
				bin_n_x = bc->PutSharedINGate(S2[x].bin_number, (uint32_t) 32);
				bin_n_y = bc->PutSharedINGate(S2[i].bin_number, (uint32_t) 32);
				shr_bin_number_eqs[i] = bc->PutEQGate(bin_n_x, bin_n_y);
				px = bc->PutSharedINGate(p[x], (uint32_t) 32);
				py = bc->PutSharedINGate(p[i], (uint32_t) 32);
				shr_sums[i] = bc->PutADDGate(px, py);
				shr_bin_number_eqs[i] = bc->PutSharedOUTGate(shr_bin_number_eqs[i]);
				shr_sums[i] = bc->PutSharedOUTGate(shr_sums[i]);
			}
		}
		party->ExecCircuit();
		for (uint32_t i = 0; i < S2.size(); i++){
			if (i/region_size % 2 == 1){
				bin_number_eqs[i] = shr_bin_number_eqs[i]->get_clear_value<uint32_t>();
				sums[i] = shr_sums[i]->get_clear_value<uint32_t>();
			}
		}
		party->Reset();

		for (uint32_t i = 0; i < S2.size(); i++){
			uint32_t region = i/region_size;
			if (region % 2 == 1){
				uint32_t x = region * region_size - 1;

				share * sum, * bin_number_eq, * py;
				bin_number_eq = bc->PutSharedINGate(bin_number_eqs[i], (uint32_t) 32);
				py = bc->PutSharedINGate(p[i], (uint32_t) 32);
				sum = bc->PutSharedINGate(sums[i], (uint32_t) 32);
				shr_p[i] = bc->PutMUXGate(sum, py, bin_number_eq);
				shr_p[i] = bc->PutSharedOUTGate(shr_p[i]);
			}
		}
		party->ExecCircuit();
		for (uint32_t i = 0; i < S2.size(); i++){
			if (i/region_size % 2 == 1){
				p[i] = shr_p[i]->get_clear_value<uint32_t>();
			}
		}
		party->Reset();
		region_size *= 2;
	}

	share* one = bc->PutCONSGate((uint64_t) 1, (uint32_t) 32);
	for (uint32_t i = 0; i < S2.size(); i++){
		shr_p[i] = bc->PutSharedINGate(p[i], (uint32_t) 32);
		shr_p[i] = bc->PutSUBGate(shr_p[i], one);
		shr_p[i] = bc->PutSharedOUTGate(shr_p[i]);
	}
	party->ExecCircuit();
	for (uint32_t i = 0; i < S2.size(); i++){
		p[i] = shr_p[i]->get_clear_value<uint32_t>();
	}
	party->Reset();

	return p;
}

std::vector<uint32_t>calc_ii(const std::vector<bin> & S2, ABYParty * party, BooleanCircuit* bc, const std::vector<uint32_t> & p, uint32_t max_bin_number){

	std::vector<uint32_t> ii(S2.size());
	
	std::vector<share*> shr_ii(S2.size());
	share* m = bc->PutCONSGate(max_bin_number, (uint32_t) 32);
	share * n;
	for (uint32_t i = 0; i < S2.size(); i++){
		n = bc->PutSharedINGate(S2[i].bin_number, (uint32_t) 32);
		shr_ii[i] = bc->PutSharedINGate(p[i], (uint32_t) 32);
		shr_ii[i] = bc->PutMULGate(shr_ii[i], m);
		shr_ii[i] = bc->PutADDGate(shr_ii[i], n);
		shr_ii[i] = bc->PutSharedOUTGate(shr_ii[i]);
	}
	party->ExecCircuit();
	for (uint32_t i = 0; i < S2.size(); i++){
		ii[i] = shr_ii[i]->get_clear_value<uint32_t>();
	}
	party->Reset();
	return ii;
}

void AlignTable(std::vector<bin> & S2, ABYParty * party, BooleanCircuit* bc, uint32_t max_bin_number){
	std::vector<uint32_t> p = calc_p(S2, party, bc);

	std::vector<uint32_t> ii = calc_ii(S2, party, bc, p, max_bin_number);
	
	std::vector<uint64_t> by;
	for (uint32_t i = 0; i < S2.size(); i++){
		by.push_back(S2[i].tag);
		by[i] = by[i] << 32;
		by[i] += ii[i];
	}
	QuickSort(party, bc, S2, by, 0, S2.size() - 1);
	return;
}

uint32_t ncomparisons(const std::vector<bin> & T1, const std::vector<bin> & T2){
	uint32_t bin_size = T1[0].data.size();
	uint32_t num_bins = T1.size();
	uint32_t size = bin_size * bin_size * num_bins;
	return size;
};

std::vector<uint32_t> intersect(const std::vector<bin> & T1, const std::vector<bin> & T2, ABYParty * party, BooleanCircuit * bc){
	uint32_t bin_size = T1[0].data.size();
	uint32_t num_bins = T1.size();
	uint32_t size = bin_size * bin_size * num_bins;
	std::vector<uint32_t> T1expanded, T2expanded;
	for (uint32_t i = 0; i < num_bins; i++){
		for (uint32_t j = 0; j < bin_size; j ++){
			for (uint32_t k = 0; k < bin_size; k++){
				T1expanded.push_back(T1[i].data[j]);
				T2expanded.push_back(T2[i].data[k]);
			}
		}
	}

	share * shr_T1 = bc->PutSharedSIMDINGate(size, T1expanded.data(), (uint32_t) 32);
	share * shr_T2 = bc->PutSharedSIMDINGate(size, T2expanded.data(), (uint32_t) 32);

	uint32_t z = 0;
	share* nmatch = bc->PutSIMDCONSGate(size, &z, (uint32_t) 32);
	nmatch = bc->PutINVGate(nmatch);
	share * comp = bc->PutEQGate(shr_T1, shr_T2);
	share * res_shr = bc->PutMUXGate(shr_T1, nmatch, comp);

	share * out_shr = bc->PutOUTGate(res_shr, ALL);

	party->ExecCircuit();

	uint32_t* out;
	uint32_t tmpbitlen, tmpnvals;
	
	out_shr->get_clear_value_vec(&out, &tmpbitlen, &tmpnvals);

	party->Reset();

	std::vector<uint32_t> match;

	for (int i = 0; i < size; i++){
		if (out[i] != 0xFFFFFFFF){
			match.push_back(out[i]);
		}
	}

	party->Reset();

	return match;
}

Timer::Timer(){
	m_Start = std::chrono::system_clock::now();
	m_End = std::chrono::system_clock::now();
	m_Running = false;
};

void Timer::start(){
	m_Start = std::chrono::system_clock::now();
	m_Running = true;
}

void Timer::stop(){
	m_End = std::chrono::system_clock::now();
	m_Running = false;
}

double Timer::elapsedSeconds(){
	std::chrono::time_point<std::chrono::system_clock> endTime;
	if (m_Running){
		endTime = std::chrono::system_clock::now();
	}
	else{
		endTime = m_End;
	}
	double ms = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - m_Start).count();
	return ms / 1000;
}

std::vector<std::string> split(const std::string & s, const std::string & by){
	std::string regular_exp = "([^" + by + "]*)(?:" + by + "(.*))?";
    std::regex re(regular_exp);
    std::smatch match;
    std::vector<std::string> output;
	std::string c = s;
    while (std::regex_search(c, match, re) == true){
        output.push_back(match.str(1));
        if (match.size() == 2){
            break;
        }
        c = match.str(2);
    }
    return output;
}

int find_communication(const std::string & s){
	std::vector<std::string> v = split(s, "\n");
	std::string regular_exp = "Total Sent /Rcv";
	regular_exp += "\\s+([0123456789]+)\\s+bytes / ([0123456789]+)\\s+bytes";
	std::regex re(regular_exp);
	int total_sent = 0;
	for (std::string line : v){
		std::smatch match;
    	bool success = std::regex_search(line, match, re);
		if (success && match.size() == 3){
			total_sent+= std::stoi(match.str(1));
		}
	}
	return total_sent;
}