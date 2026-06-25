use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    thread,
};

const DATA_DIR: &str = "./data";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: benchmark <EXAMPLE_NAME> <NUM_PROCESSES> <NUM_REPEATS>");
        std::process::exit(1);
    }

    let example_name = &args[1];
    let num_processes: usize = args[2].parse().expect("Invalid NUM_PROCESSES");
    let num_repeats: usize = args[3].parse().expect("Invalid NUM_REPEATS");

    let build_status = Command::new("cargo")
        .args(["build", "--release", "--example", example_name])
        .env("RUSTFLAGS", "-C target-cpu=native")
        .status()
        .expect("Failed to run cargo build");

    if !build_status.success() {
        eprintln!("Compilation failed");
        std::process::exit(1);
    }

    fs::create_dir_all(DATA_DIR).expect("Failed to create data directory");

    for entry in fs::read_dir(DATA_DIR).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |ext| ext == "txt") {
            fs::remove_file(path).unwrap();
        }
    }

    let data_file_path = format!("{}/{}_local", DATA_DIR, num_processes);
    let mut data_file = File::create(&data_file_path).expect("Failed to create data file");

    for i in 0..num_processes {
        let port = 8000 + i;
        writeln!(data_file, "127.0.0.1:{}", port).unwrap();
    }

    for r in 0..num_repeats {
        println!("Running repeat {} / {}", r + 1, num_repeats);
        let mut handles = vec![];

        for i in 0..num_processes {
            let example_name = example_name.clone();
            let data_file_path = data_file_path.clone();

            let handle = thread::spawn(move || {
                let bin_path = format!("../target/release/examples/{}", example_name);
                let status = Command::new("taskset")
                    .arg("-c")
                    .arg(i.to_string())
                    .arg(&bin_path)
                    .arg(i.to_string())
                    .arg(&data_file_path)
                    .env("RAYON_NUM_THREADS", "1")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("Failed to start subprocess");

                assert!(status.success());
            });

            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    println!("\n======= Average Timing Results =======");

    let mut total_avgs_commu = 0.0;

    for i in 0..num_processes {
        let file_path = format!("{}/{}.txt", DATA_DIR, i);
        let file =
            File::open(&file_path).unwrap_or_else(|_| panic!("Failed to open {}", file_path));
        let reader = BufReader::new(file);

        let mut sums: Vec<f64> = vec![];
        let mut count = 0;

        for line in reader.lines() {
            let line = line.unwrap();
            let times: Vec<f64> = line
                .split(',')
                .map(|s| s.trim().parse::<f64>().unwrap())
                .collect();

            if sums.is_empty() {
                sums = vec![0.0; times.len()];
            }

            for (j, t) in times.iter().enumerate() {
                sums[j] += t;
            }

            count += 1;
        }

        // * 1000 to transform s to ms
        let avgs: Vec<f64> = sums
            .iter()
            .map(|sum| (sum / count as f64) * 1000.0)
            .collect();
        let mut new_avgs = vec![];
        new_avgs.push(format!("{:.3}", &avgs[0] + &avgs[1]));
        new_avgs.push(format!("{:.3}", &avgs[4] - &avgs[2] - &avgs[3]));
        if avgs.len() == 6 {
            new_avgs.push(format!("{:.3}", 0.0));
            new_avgs.push(format!("{:.3}", 0.0));
            new_avgs.push(format!("{:.3}", &avgs[5]));

            total_avgs_commu += avgs[5];
        } else {
            new_avgs.push(format!("{:.3}", &avgs[5]));
            new_avgs.push(format!("{:.3}", &avgs[6]));
            new_avgs.push(format!("{:.3}", &avgs[7]));

            total_avgs_commu += avgs[7];
        }

        println!("Process {:<2}: [commit times (ms), open times (ms), proof size (KB), verifier time(ms), communication (KB)] = [{}]", i, new_avgs.join(", "));

        fs::remove_file(&file_path).unwrap();
    }

    println!("Total communication: {} KB", total_avgs_commu);
}