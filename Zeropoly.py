from collections import defaultdict
def Zero_poly(a, n, item1, item2):
    if n >= 0:
        mult = defaultdict(int)
        for i1, c1 in zip([1,0], [1, a[n]]):
            for i2, c2 in zip(item1, item2):
                mult[i1 + i2] += c1 * c2
        mult_sorted = tuple(sorted(mult.items(), reverse=True))
        item1 = [item[0] for item in mult_sorted]
        item2 = [item[1] for item in mult_sorted]
        a=a[:n]
        return Zero_poly(a, n - 1, item1, item2)
    else:
       return (item1,item2)
