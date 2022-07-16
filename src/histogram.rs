pub fn histogram(values: &[f64], bins: usize) -> Vec<(f64, usize)> {
    assert!(bins >= 2);
    let mut bucket: Vec<usize> = vec![0; bins];
    let min = values.iter().collect::<average::Min>().min();
    let max = values.iter().collect::<average::Max>().max();
    let step = (max - min) / (bins - 1) as f64;

    for &v in values {
        let i = std::cmp::min(((v - min) / step).ceil() as usize, bins - 1);
        bucket[i] += 1;
    }

    bucket
        .into_iter()
        .enumerate()
        .map(|(i, v)| (min + step * i as f64, v))
        .collect()
}
