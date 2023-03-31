from math import floor, ceil
from random import seed, randint
from collections_extended import bag
import editdistance
from datasketch import MinHash
import numpy as np
from time import time
import pandas as pd
from json import load, dump
from sympy import randprime
import csv
from os import path
import argparse
from multiprocessing import Pool

saved_hashes = None
out_count = np.empty(shape=[0, ])
hash_count = 0
hash_time = 0.0
large_p = None


class Bin:
    def __init__(self, tag, elements=None, link=lambda x, y: x == y):
        self.tag = tag
        if elements is None:
            elements = bag()
        self.elements = bag(elements)
        self.link = link
        self.comparison_count = 0

    def append(self, element):
        self.elements.add(element)

    def link_with(self, other):
        elements = bag()
        for e1 in self.elements:
            for e2 in other.elements:
                self.comparison_count += 1
                if self.link(e1, e2):
                    elements.add((e1, e2))
        return Bin(self.tag, elements, self.link)

    def __repr__(self):
        return f"Bin with tag {self.tag}, and content {self.elements}"


class Bins:
    def __init__(self, elements, h, link):
        bins = dict()
        self.bins = set()
        element_count = 0
        for e in elements:
            h_values = h(e)
            for h_value in h_values:
                element_count += 1
                if h_value in bins:
                    bins[h_value].append(e)
                else:
                    bins[h_value] = Bin(h_value, [e], link)
        self.bins = bins

        self.n = len(self.bins)
        self.m = element_count
        self.max_bin_size = floor(self.m / self.n)

    def __repr__(self):
        out = ""
        for b in self.bins.values():
            out += f"Bin {b}\n"
        return out

    def clear_comparison_count(self):
        for b in self.bins.values():
            b.comparison_count = 0

    def sum_comparison_count(self):
        res = 0
        for b in self.bins.values():
            res += b.comparison_count
        return res

    def link_with(self, other):
        result = bag()
        self.clear_comparison_count()
        for b in self.bins.values():
            tag = b.tag
            if tag in other.bins:
                linked = b.link_with(other.bins[tag])
                for e in linked.elements:
                    result.add(e)
        return result, self.sum_comparison_count()


def join(a, b, lsh, match):
    l = lambda x: [int(y) for y in lsh(x)]
    binsA = Bins(a, l, match)
    binsB = Bins(b, l, match)

    print("start linking...")

    join_result, comparison_count = binsA.link_with(binsB)

    print("end linking")

    return join_result, comparison_count


def test(a, b, lsh, match, gt):
    join_result, num_comparisons = join(a, b, lsh, match)
    real_result = set(gt)
    join_result = set(join_result)

    acc = len(real_result.intersection(join_result)) / len(real_result.union(join_result))

    fp = join_result.difference(real_result)
    fn = real_result.difference(join_result)

    for a, g in fn:
        print(f"fn: {a}")
        print(f"    {g}")

    return acc, num_comparisons, fp, fn


def test_hash_with_gt(lsh, gt):
    match_count = 0
    fn = list()
    for a, b in gt:
        bh = lsh(b)
        match = False
        for v in lsh(a):
            if v in bh:
                match = True
        if match:
            match_count += 1
        else:
            fn.append((a, b))
    return match_count / len(gt)


def test_random_numbers(num_elements, num_bins, min_val=0, max_val=1e10):
    seed(1)
    num_elements = int(num_elements)
    min_val = int(min_val)
    max_val = int(max_val)
    a = [randint(min_val, int(max_val) - 1) for _ in range(num_elements)]
    b = [randint(min_val, int(max_val) - 1) for _ in range(num_elements)]

    interval = (max_val - min_val) // num_bins
    lsh = lambda x: (x - min_val) // interval
    match = lambda x, y: x == y

    real_result = [(x, x) for x in set(a).intersection(b)]

    return test(a, b, lsh, match, real_result)


def test_amazon_google(lsh, match):
    gt_path = "Amazon-GoogleProducts/Amazon_Google_Products_perfectMapping.csv"
    amazon_path = "Amazon-GoogleProducts/Amazon_Products.csv"
    google_path = "Amazon-GoogleProducts/Google_Products.csv"

    gt_df = pd.read_csv(gt_path, dtype=object, delimiter=',', quotechar='"')
    amazon_df = pd.read_csv(amazon_path, dtype=object, delimiter=',', quotechar='"')
    google_df = pd.read_csv(google_path, dtype=object, delimiter=',', quotechar='"')

    amazon_df = amazon_df[['idAmazon', 'title', 'description']].dropna()
    # amazon_df['description'] = amazon_df['title']
    amazon_df['description'] = amazon_df['title'] + amazon_df['description']
    amazon_df = amazon_df[['idAmazon', 'description']]
    google_df = google_df[['idGoogleBase', 'name', 'description']].dropna()
    # google_df['description'] = google_df['name']
    google_df['description'] = google_df['name'] + google_df['description']
    google_df = google_df[['idGoogleBase', 'description']]

    gt_df = gt_df.dropna()

    gt_df = google_df.merge(gt_df, on='idGoogleBase', how='inner').merge(amazon_df, on='idAmazon', how='inner')
    gt_df.to_csv('gt.csv')

    gt = [(a, g) for a, g in zip(gt_df['description_x'], gt_df['description_y'])]

    amazon = [a for a in amazon_df['description']]
    google = [g for g in google_df['description']]
    semantic_gt = set(gt)

    # set_gt = semantic_gt
    set_gt = set()
    for a in amazon:
        for g in google:
            if match(a, g, semantic_gt):
                set_gt.add((a, g))
                print(f"{a}\n {g}\n")

    print(f"finish calculating ground truth, {len(set_gt)} pairs of records in gt")

    return test(amazon, google, lsh, lambda x, y: match(x, y, set_gt), set_gt)


class Book:
    def __init__(self, ISBN, title, author_first_name, author_last_name):
        self.isbn = ISBN
        self.title = title
        self.author_first_name = author_first_name
        self.author_last_name = author_last_name
        self.author = author_first_name + author_last_name

    def __repr__(self):
        return f"({self.title}, {self.isbn}, {self.author})"

    def to_list(self):
        return [self.isbn, self.title, self.author_first_name, self.author_last_name]

    def desc(self):
        return f"({self.title}|{self.isbn}|{self.author})"

    def __eq__(self, other):
        return self.isbn == other.isbn

    def __hash__(self):
        return hash(self.isbn)


class Library:
    def __init__(self):
        self.books = set()

    def __iter__(self):
        return iter(self.books)

    def __len__(self):
        return len(self.books)

    def from_file(self, filename):
        f = open(filename, 'r')
        data = load(f)
        f.close()
        self.books = set([Book(x[0], x[1], x[2], x[3]) for x in data])

    def from_set(self, books):
        self.books = set(books)

    def sample(self, rate=1.0, num=None):
        list_books = list(self.books)
        list_books.sort(key=lambda x: x.isbn)
        if not num:
            num = ceil(len(list_books) * rate)
        list_books = list_books[:num]
        new_books = set()
        for b in list_books:
            new_books.add(b)
        self.books = new_books

    def to_list(self):
        return [x.to_list() for x in self.books]

    def to_file(self, filename):
        f = open(filename, 'w')
        dump(self.to_list(), f)
        f.close()

    def to_dict(self):
        out = dict()
        for book in self.books:
            out[book.isbn] = book
        return out

    def intersection(self, other):
        result = Library()
        result.from_set(self.books.intersection(other.books))
        return result


class Voter:
    def __init__(self, ncid, first_name, midl_name, last_name, birth_yr, birth_place):
        self.ncid = ncid
        self.first_name = first_name
        self.last_name = last_name
        self.midl_name = midl_name
        self.birth_yr = birth_yr
        self.birth_place = birth_place

    def __repr__(self):
        return f"({self.ncid}, {self.first_name}, {self.last_name}, {self.midl_name})"

    def to_list(self):
        return [self.ncid, self.first_name, self.last_name, self.midl_name]

    def desc(self):
        return f"({self.first_name}|{self.last_name}|{self.midl_name}|{self.birth_yr}|{self.birth_place})"

    def __eq__(self, other):
        return self.ncid == other.ncid

    def __hash__(self):
        return hash(self.ncid)


def sample_ncvr(srcname, records, destname):
    df = pd.read_csv(srcname, delimiter="\t", quotechar="\"", encoding="utf-16 LE")
    df = df.dropna(subset=['ncid', 'first_name', "midl_name", "last_name", "age", "birth_place"])
    df = df.drop_duplicates(subset=['ncid', 'first_name', "midl_name", "last_name", "age", "birth_place"])
    df.sort_values(by=['ncid'], inplace=True)
    df.head(records).to_csv(destname, sep="\t", quotechar="\"", encoding="utf-16 LE")
    del df


class Snapshot:
    def __init__(self):
        self.voters = set()

    def __iter__(self):
        return iter(self.voters)

    def __len__(self):
        return len(self.voters)

    def from_file(self, filename):
        df = pd.read_csv(filename, delimiter="\t", quotechar="\"", encoding="utf-16 LE")
        self.voters = set([Voter(x["ncid"], x["first_name"], x["midl_name"], x["last_name"], str((int(x["snapshot_dt"][:4]) - x["age"])), x['birth_place']) for it, x in df.iterrows()])

    def from_set(self, voters):
        self.voters = set(voters)

    def sample(self, rate=1.0, num=None):
        list_voters = list(self.voters)
        list_voters.sort(key=lambda x: x.ncid)
        if not num:
            num = ceil(len(list_voters) * rate)
        list_voters = list_voters[:num]
        new_voters = set()
        for b in list_voters:
            new_voters.add(b)
        self.voters = new_voters

    def to_list(self):
        return [x.to_list() for x in self.voters]

    def to_file(self, filename):
        f = open(filename, 'w')
        dump(self.to_list(), f)
        f.close()

    def to_dict(self):
        out = dict()
        for voters in self.voters:
            out[voters.ncid] = voters
        return out

    def intersection(self, other):
        result = Snapshot()
        result.from_set(self.voters.intersection(other.books))
        return result


def get_hash_result(lsh, A):
    hash_results = dict()
    for a in A:
        ha = lsh(a)
        for hv in ha:
            if hv in hash_results:
                hash_results[hv] += 1
            else:
                hash_results[hv] = 1
    return hash_results


def calculate_comparisons(lsh, A, B):
    hash_A = get_hash_result(lsh, A)
    hash_B = get_hash_result(lsh, B)

    comparison_count = 0

    for hv in hash_A:
        if hv in hash_B:
            comparison_count += hash_A[hv] * hash_B[hv]

    return comparison_count


def test_bnb_tpl_single(param, n_sample=10000, silent=True):
    bnb = Library()
    bnb.from_file("bnb_tpl_datasets/bnb_cleaned.json")
    bnb.sample(num=n_sample)
    tpl = Library()
    tpl.from_file("bnb_tpl_datasets/tpl_cleaned.json")
    tpl.sample(num=n_sample)

    bnb_gt = bnb.to_dict()
    tpl_gt = tpl.to_dict()
    gt = set()
    for isbn in tpl_gt.keys():
        if isbn in bnb_gt.keys():
            gt.add((bnb_gt[isbn], tpl_gt[isbn]))

    if not silent:
        print(f"bnb records: {len(bnb)}")
        print(f"tpl records: {len(tpl)}")
        print(f"ground truth records: {len(gt)}")

    minHash = MyMinHash(min_hash_param=param)
    lsh = lambda x: minHash.hash(x.desc())
    l = lambda x: [int(y) for y in lsh(x)]

    accuracy = test_hash_with_gt(l, gt)
    print(f"accuracy: {accuracy}")

    comparison_count = calculate_comparisons(l, bnb, tpl)

    return accuracy, comparison_count


def calculate_comparison_accuracy(parameter):
    param, x, y, gt = parameter
    minHash = MyMinHash(min_hash_param=param)
    lsh = lambda x: minHash.hash(x.desc())
    l = lambda x: [int(y) for y in lsh(x)]

    accuracy = test_hash_with_gt(l, gt)

    comparison = calculate_comparisons(l, x, y)

    return accuracy, comparison


def calculate_comparisons_accuracies(params, x, y, gt):
    accuracies = list()
    comparisons = list()

    with Pool(len(params)) as p:
        results = p.map(calculate_comparison_accuracy, [(param, x, y, gt) for param in params])
        for res in results:
            accuracy, comparison_count = res
            accuracies.append(accuracy)
            comparisons.append(comparison_count)

    return accuracies, comparisons


def test_bnb_tpl(params, n_sample=10000, silent=True):
    bnb = Library()
    bnb.from_file("bnb_tpl_datasets/bnb_cleaned.json")
    bnb.sample(num=n_sample)
    tpl = Library()
    tpl.from_file("bnb_tpl_datasets/tpl_cleaned.json")
    tpl.sample(num=n_sample)

    bnb_gt = bnb.to_dict()
    tpl_gt = tpl.to_dict()
    gt = set()
    for isbn in tpl_gt.keys():
        if isbn in bnb_gt.keys():
            gt.add((bnb_gt[isbn], tpl_gt[isbn]))

    # if not silent:
    print(f"bnb records: {len(bnb)}")
    print(f"tpl records: {len(tpl)}")
    print(f"ground truth records: {len(gt)}")

    accuracies, comparisons = calculate_comparisons_accuracies(params, bnb, tpl, gt)

    return accuracies, comparisons, len(gt)


def test_ncvr(params, n_sample=10000):
    if not path.exists(f"NCVR/14_{n_sample}.txt"):
        if path.exists(f"NCVR/14_100000.txt") and n_sample < 100000:
            sample_ncvr("NCVR/14_100000.txt", n_sample, f"NCVR/14_{n_sample}.txt")
        else:
            sample_ncvr("NCVR/VR_Snapshot_20140101.txt", n_sample, f"NCVR/14_{n_sample}.txt")
    if not path.exists(f"NCVR/17_{n_sample}.txt"):
        if path.exists(f"NCVR/17_100000.txt") and n_sample < 100000:
            sample_ncvr("NCVR/17_100000.txt", n_sample, f"NCVR/17_{n_sample}.txt")
        else:
            sample_ncvr("NCVR/VR_Snapshot_20170101.txt", n_sample, f"NCVR/17_{n_sample}.txt")
    ncvr14 = Snapshot()
    ncvr14.from_file(f"NCVR/14_{n_sample}.txt")
    ncvr17 = Snapshot()
    ncvr17.from_file(f"NCVR/17_{n_sample}.txt")

    ncvr14_dict = ncvr14.to_dict()
    ncvr17_dict = ncvr17.to_dict()
    gt = set()
    for ncid in ncvr14_dict.keys():
        if ncid in ncvr17_dict.keys():
            gt.add((ncvr14_dict[ncid], ncvr17_dict[ncid]))

    # if not silent:
    print(f"ncvr14 records: {len(ncvr14)}")
    print(f"ncvr17 records: {len(ncvr17)}")
    print(f"ground truth records: {len(gt)}")

    accuracies, comparisons = calculate_comparisons_accuracies(params, ncvr14, ncvr17, gt)

    return accuracies, comparisons, len(gt)


def inv_quantile(a, e):
    return np.searchsorted(a, e) / a.size


def process_string(s, n_grams=3):
    result = []
    for i in range(len(s) - n_grams + 1):
        result.append(s[i:i + n_grams])
    return result


def get_digest(s, num_perms=128):
    h = MinHash(num_perm=num_perms)
    if isinstance(s, str):
        s = process_string(s, 4)
    for e in s:
        h.update(e.encode('utf-8'))
    return h.digest()


def hash_int(i, b_from, b_to):
    global large_p
    if large_p is None:
        large_p = randprime(2 ** 32, 2 ** 33)
    return i * large_p % (b_to - b_from) + b_from


class MinHashParams:
    def __init__(self, num_bins=16, num_perms=128, num_duplicates=4):
        self.num_bins = num_bins
        self.num_perms = num_perms
        self.num_duplicates = num_duplicates


class MyMinHash:
    def __init__(self, num_bins=16, num_perms=128, num_duplicates=4, min_hash_param: MinHashParams = None):
        if min_hash_param is not None:
            num_bins = min_hash_param.num_bins
            num_perms = min_hash_param.num_perms
            num_duplicates = min_hash_param.num_duplicates
        self.__large_prime = randprime(2 ** 32, 2 ** 33)
        self.__num_bins = num_bins
        self.__num_perms = num_perms
        self.__num_duplicates = num_duplicates
        assert not (num_bins % num_duplicates)
        self.__bins_per_duplicate = num_bins // num_duplicates
        self.__hash_count = 0
        self.__hash_time = 0
        self.__out_count = np.empty(shape=[0, ])
        self.__filters = list()
        # select_probability = 1 / num_duplicates
        perms_per_duplicate = self.__num_perms // self.__num_duplicates
        for i in range(num_duplicates):
            lower_bound = i * perms_per_duplicate
            upper_bound = lower_bound + perms_per_duplicate
            self.__filters.append(np.array([1 if lower_bound <= x < upper_bound else 0 for x in range(num_perms)]))
            # self.__filters.append(np.random.choice(2, num_perms, p=[1 - select_probability, select_probability]))

    def hash(self, strings):
        self.__hash_count += 1
        start = time()
        digest = get_digest(strings, self.__num_perms)
        hashes = [digest[f == 1].sum() for f in self.__filters]

        out = []
        for i in range(self.__num_duplicates):
            start_index = i * self.__bins_per_duplicate
            out.append(self.__hash_int__(hashes[i], start_index, start_index + self.__bins_per_duplicate))
        self.__out_count = np.concatenate((self.__out_count, out))
        end = time()
        self.__hash_time += end - start
        return out

    def bin_stats(self):
        unique_bins = np.unique(self.__out_count)
        for b in unique_bins:
            print(f"bin #{b} has {(self.__out_count == b).sum()} elements")

    def hash_stats(self):
        print(f"average hash time: {self.__hash_time / self.__hash_count} seconds")

    def __hash_int__(self, i, b_from, b_to):
        return int(i) * self.__large_prime % (b_to - b_from) + b_from


def min_hash(strings, num_bins=16, num_perms=128, write=False, num_duplicates=4):
    assert not (num_bins % num_duplicates)
    global saved_hashes, out_count, hash_count, hash_time
    hash_count += 1
    start = time()
    digest = get_digest(strings, num_perms)

    filters = list()
    select_probability = 1 / num_duplicates
    for _ in range(num_duplicates):
        filters.append(np.random.choice(2, num_perms, p=[1 - select_probability, select_probability]))

    hashes = [digest[f == 1].mean() for f in filters]

    bins_per_duplicate = num_bins / num_duplicates

    out = []
    for i in range(num_duplicates):
        out.append(hash_int(hashes[i], i, i + bins_per_duplicate))
    out_count = np.concatenate((out_count, out))
    end = time()
    hash_time += end - start
    return out


def hash_book(book, num_bins=16, num_perms=128, write=False, num_duplicates=4):
    strings = book.title + "|" + book.author
    result = min_hash(strings, num_bins, num_perms, write, num_duplicates)
    return result


def hash_voter(voter, num_bins=16, num_perms=128, write=False, num_duplicates=4):
    strings = voter.birth_yr + "|" + voter.first_name + "|" + voter.midl_name + "|" + voter.last_name + "|" + voter.birth_place
    result = min_hash(strings, num_bins, num_perms, write, num_duplicates)
    return result


def string_match(a, b, thresh=0.3):
    dist = editdistance.eval(a, b)
    dist_thresh = thresh * min(len(a), len(b))
    return dist <= dist_thresh


def exact_match(a, b, pairlist):
    return (a, b) in pairlist


def init_hash_list(filename, num_perms=128):
    f = open(filename, "r")
    for line in f.readlines():
        min_hash(line, num_perms=num_perms, write=True)
    f.close()


def bin_stats():
    unique_bins = np.unique(out_count)
    for b in unique_bins:
        print(f"bin #{b} has {(out_count == b).sum()} elements")


def hash_stats():
    print(f"average hash time: {hash_time - hash_count} seconds")


def hash_function_creator(min_hash):
    return lambda x: min_hash.hash(x.desc())


def test_bnb_tpl_set(num_bins_per_duplicate_range, num_perms_per_hash_range, num_duplicates_range, n_sample):

    seed(int(time()))
    min_hash_params = list()
    for num_bins_per_duplicate in num_bins_per_duplicate_range:
        for num_perms_per_hash in num_perms_per_hash_range:
            for num_duplicates in num_duplicates_range:
                num_bins = num_bins_per_duplicate * num_duplicates
                num_perms = num_perms_per_hash * num_duplicates

                min_hash_params.append(MinHashParams(num_bins=num_bins, num_perms=num_perms, num_duplicates=num_duplicates))

    ts = time()
    results = list()
    for n_samp in n_sample:
        accuracies, comparisons, n_gt = test_bnb_tpl(min_hash_params, n_sample=n_samp)
        results.append((accuracies, comparisons, n_gt))
    te = time()

    prefix = "bnb_tpl_exp"
    num_exp = 0
    while path.exists(f"{prefix}_{num_exp}.csv"):
        num_exp += 1

    with open(f"{prefix}_{num_exp}.csv", 'w', newline='') as outfile:
        csvwriter = csv.writer(outfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(
            ["number_of_samples", "ground_truth_records", "num_bins_per_duplicate", "num_permutations_per_hash", "num_duplicates",
             "num_comparisons", "accuracy"])
        for n_samp, result in zip(n_sample, results):
            accuracies, comparisons, n_gt = result
            run_number = 0
            for num_bins_per_duplicate in num_bins_per_duplicate_range:
                for num_perms_per_hash in num_perms_per_hash_range:
                    for num_duplicates in num_duplicates_range:
                        accuracy = accuracies[run_number]
                        comparison = comparisons[run_number]
                        run_number += 1
                        csvwriter.writerow(
                            [f"{n_samp}", f"{n_gt}", f"{num_bins_per_duplicate}", f"{num_perms_per_hash}", f"{num_duplicates}",
                             f"{comparison}", f"{accuracy}"])
                        print(f"comparison: {comparison}, accuracy: {accuracy}")
    print(f"time used: {te - ts} seconds.")


def test_ncvr_set(num_bins_per_duplicate_range, num_perms_per_hash_range, num_duplicates_range, n_sample):

    seed(int(time()))
    min_hash_params = list()

    for num_bins_per_duplicate in num_bins_per_duplicate_range:
        for num_perms_per_hash in num_perms_per_hash_range:
            for num_duplicates in num_duplicates_range:
                num_bins = num_bins_per_duplicate * num_duplicates
                num_perms = num_perms_per_hash * num_duplicates

                min_hash_params.append(MinHashParams(num_bins=num_bins, num_perms=num_perms, num_duplicates=num_duplicates))

    ts = time()
    results = list()
    for n_samp in n_sample:
        accuracies, comparisons, n_gt = test_ncvr(min_hash_params, n_sample=n_samp)
        results.append((accuracies, comparisons, n_gt))
    te = time()

    prefix = "ncvr_exp"
    num_exp = 0
    while path.exists(f"{prefix}_{num_exp}.csv"):
        num_exp += 1

    with open(f"{prefix}_{num_exp}.csv", 'w', newline='') as outfile:
        csvwriter = csv.writer(outfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(
            ["number_of_samples", "ground_truth_records", "num_bins_per_duplicate", "num_permutations_per_hash", "num_duplicates",
             "num_comparisons", "accuracy"])
        for n_samp, result in zip(n_sample, results):
            accuracies, comparisons, n_gt = result
            run_number = 0
            for num_bins_per_duplicate in num_bins_per_duplicate_range:
                for num_perms_per_hash in num_perms_per_hash_range:
                    for num_duplicates in num_duplicates_range:
                        accuracy = accuracies[run_number]
                        comparison = comparisons[run_number]
                        run_number += 1
                        csvwriter.writerow(
                            [f"{n_samp}", f"{n_gt}", f"{num_bins_per_duplicate}", f"{num_perms_per_hash}", f"{num_duplicates}",
                             f"{comparison}", f"{accuracy}"])
                        print(f"comparison: {comparison}, accuracy: {accuracy}")
    print(f"time used: {te - ts} seconds.")


def main():
    parser = argparse.ArgumentParser(
        prog='PlainPRL',
        description='Plaintext record linkage with sampling')

    parser.add_argument('-n', '--num_samples', default="-1")
    parser.add_argument('-t', '--test_name', default="bnb_tpl", choices=['bnb_tpl','ncvr'])

    args = parser.parse_args()

    n_sample = int(args.num_samples)
    test = args.test_name

    num_bins_per_duplicate_range = [1024, 2048]
    num_perms_per_hash_range = [2]
    num_duplicates_range = [8, 16, 32]
    n_sample_range = [10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000, 90000]

    if n_sample == -1:
        if test == "bnb_tpl":
            test_bnb_tpl_set(num_bins_per_duplicate_range=num_bins_per_duplicate_range,
                             num_perms_per_hash_range=num_perms_per_hash_range,
                             num_duplicates_range=num_duplicates_range,
                             n_sample=n_sample_range)
        else:
            test_ncvr_set(num_bins_per_duplicate_range=num_bins_per_duplicate_range,
                          num_perms_per_hash_range=num_perms_per_hash_range,
                          num_duplicates_range=num_duplicates_range,
                          n_sample=n_sample_range)
    else:
        if test == "bnb_tpl":
            test_bnb_tpl_set(num_bins_per_duplicate_range=num_bins_per_duplicate_range,
                             num_perms_per_hash_range=num_perms_per_hash_range,
                             num_duplicates_range=num_duplicates_range,
                             n_sample=[n_sample])
        else:
            test_ncvr_set(num_bins_per_duplicate_range=num_bins_per_duplicate_range,
                          num_perms_per_hash_range=num_perms_per_hash_range,
                          num_duplicates_range=num_duplicates_range,
                          n_sample=[n_sample])

    print("done")

if __name__ == '__main__':
    main()
