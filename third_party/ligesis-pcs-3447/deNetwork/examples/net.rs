use std::env;

use deNetwork::{DeMultiNet as Net, DeNet, DeSerNet};

fn test_send() {
    let long_message = vec![1u8; 1 << 20];
    let val = Net::send_to_master(&long_message);
    if Net::am_master() {
        let val = val.unwrap();
        assert_eq!(val.len(), Net::n_parties());
        for i in 0..val.len() {
            assert_eq!(val[i].len(), 1 << 20);
            for j in val[i].iter() {
                assert_eq!(*j, 1)
            }
        }
    } else {
        assert!(val == None);
    }
}

fn test_recv() {
    let long_message = vec![1u8; 1 << 20];
    let val = Net::recv_from_master_uniform(if Net::am_master() {
        Some(long_message)
    } else {
        None
    });
    assert_eq!(val.len(), 1 << 20);

    let mut data = vec![];
    for i in 0..Net::n_parties() {
        data.push((0..(1 << 20)).map(|_| i as u8).collect::<Vec<_>>());
    }
    let val = Net::recv_from_master(if Net::am_master() { Some(data) } else { None });
    assert_eq!(val.len(), 1 << 20);
    for i in val {
        assert_eq!(i, Net::party_id() as u8)
    }
}

fn main() {
    let arges = env::args().collect::<Vec<_>>();
    let party_id: usize = arges[1].parse().unwrap();
    println!("This is party {}", party_id);
    Net::init_from_file("ip.txt", party_id);
    test_send();
    println!("Send OK");
    test_recv();
    println!("Test OK");
    Net::deinit();
}
