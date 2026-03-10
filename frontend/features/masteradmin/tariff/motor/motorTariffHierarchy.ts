type MotorTariffHierarchyType = {
  [tariffType: string]: {
    [group: string]: {
      [type: string]: string[] | string[][];
    };
  };
};
export const motorTariffHierarchy:MotorTariffHierarchyType = {
    "Private Vehicle": {
        "Passenger Vehicle/Goods Carrying": {
            "Car, Car type and/or Passenger Vehicle , Goods Carrying Vehicle": [
                [
                    "Passenger Vehicles Upto 1300 CC or Goods carrying vehicles upto 1/2 ton",
                    "Passenger Vehicles Upto 1800 CC or Goods carrying vehicles upto 1-1.5 tons",
                    "Passenger Vehicles Upto 3000 CC or Goods carrying vehicles upto 3 tons",
                    "Passenger Vehicles over 3000 CC or Goods carrying vehicles over 3 tons"
                ],
            ]
        },
        "Trailer": {
            "Trailer": [
                "Carvan Trailer or any other trailers",
                "Luggage Trailer"
            ]

        }
    },
    "Motor Cycle": {
        "Auto Cycles or Mechanically Assisted Pedal Cycles": {
            "Any Motor Cycle with an engine capacity not exceeding 75 c.c. with a constant gear ratio": [
                "Not Exceeding 75 C.C."
            ]
        },
        "MotorCycle/Scooter": {
            "MotorCycle/Scooter": [
                "Upto 75 CC",
                "Upto 150 CC",
                "Upto 250 CC",
                "Upto 350 CC"
            ]
        }
    },
    "Commercial Vehicle": {
        "Class A Goods Carrying Vehicles": {
            "Goods Carrying Vehicles": [
                "Upto 3 Tons",
                "Upto 4 Tons",
                "Upto 5 Tons",
                "Upto 6 Tons",
                "Upto 7 Tons",
                "Upto 8 Tons",
                "Upto 9 Tons",
                "Upto 10 Tons",
                "Upto 11 Tons",
                "Upto 12 Tons",
                "Upto 13 Tons",
                "Upto 14 Tons",
                "Upto 15 Tons",
                "Upto 16 Tons",
                "Upto 17 Tons",
                "Upto 18 Tons",
                "Upto 19 Tons",
                "Upto 20 Tons"
            ],
            "Towing of not more than two trailers at a time": [
                "Agricultural & Foresty Vehicles Item",
                "carrige of good for hire or reward"
            ],
            "Towing of one trailer only": [
                "Agricultural & Foresty Vehicles Item",
                "carrige of good for hire or reward"
            ],
            "Towing of three or more trailers at a time": [
                "carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
        },
        "Class B(1,0) Goods Carrying Vehicles": {
            "Towing of three or more trailers at a time": [
                "Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)"
            ]
        },
        "Class B(1,0) Passenger Carrying Vehicles": {
            "Single Deck": [
                "Not Exceeding 18 Seats (Endt. 75 must be used,0)",
                "Not Exceeding 19-24 Seats  (Endt. 75 must be used,0)",
                "Not Exceeding 25-30 Seats  (Endt. 75 must be used,0)",
                "Not Exceeding 31-36 Seats  (Endt. 75 must be used,0)",
                "Over 36 Seats  (Endt. 75 must be used,0)"
            ]
            ,
            "Double Deck": [
                "Not Exceeding 60 Seats  (Endt. 75 must be used,0)",
                "Over 60 seats  (Endt. 75 must be used,0)"
            ]
        },
        "Class B(2,0) Passenger Carrying Vehicles": {
            "Taxi or Private Car type vehicles Playing for Public hire  (Endt. 75 & 76 must be used,0)": [
                "na"
            ]
        },
        "Class C Passenger Carrying Vehicles": {
            "Motorised Rickshaws used for carrying passenger for hire or Reward": [
                "Not Exceeding 350 C.C.",
                "Not Exceeding 500 C.C.",
                "Not Exceeding 750 C.C.",
                "Over 750 C.C."
            ]
        },
        "Class D Miscellaneous & Special Types of Vehicles": {
            "Agricultural & Foresty Vehicles": [
                "Agricultural Tractors Designed primarily Pedestrain Controlled and not exceeding 6 H.P.",
                "Excluding Vehicles owned by Timber Marchants and Haulers tree haulage which must be rated as Goods carrying Vehicles-Own Goods or general Cartage - Use confined to insureds farm or Concession expect as provided by Endosment No. 61",
                "Excluding Vehicles owned by Timber Marchants and Haulers tree haulage which must be rated as Goods carrying Vehicles-Own Goods or general Cartage - Use not confined to insureds farm or Concession"
            ],
            "Air Line Vehicles": [
                "Lorries and Trucks used for carrying goods luggage and stores only but excluding use for hire or reward",
                "Omnibuses and Station Wagons for carriage of passengers and crew and or crews only",
                "Plane Loaders and other vehicles used exclusive for the carriage of passenger Luggage to an from the Air port office to Aeroplanes Within the Air fields"
            ],
            "Ambulances": [
                "na"
            ],
            "Angledozers Use confined to own premises or concession": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one  trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one  trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Angledozers Use confined to own premises or concession (a,0) Tractors": [
                "Tractors (Endt. No. 61 must be used,0)"
            ],
            "Angledozers Use Not confined to own premises or concession": [

                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one  trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one  trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"

            ],
            "Angledozers Use Not confined to own premises or concession (a,0) Tractors": [
                "Tractors"
            ],
            "Anti Malarial Vans": [
                "na"
            ],
            "Breakdown Vehicles": [
                "na"
            ],
            "Bulldozers and Bullgraders Use confined to own premises or concession": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one  trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one  trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Bulldozers and Bullgraders Use confined to own premises or concession (a,0) Tractors": [
                "Tractors (Endt. No. 61 must be used,0)"
            ],
            "Bulldozers and Bullgraders Use Not confined to own premises or concession": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one  trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one  trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Bulldozers and Bullgraders Use Not confined to own premises or concession (a,0) Tractors": [
                "Tractors"
            ],
            "Cinema Film Recording and publicity": [
                "Carrying capacity exceeding 1.50 tons",
                "Carrying capacity not exceeding 1.50 tons",
                "Trailers fitted as Cinema film recording & publicity Vans (Endt. No. 43 must be used,0)"

            ],
            "Clark Tractor Elevators": [
                "Trailers",
                "Vehicles"
            ],
            "Commercial Type Vehicles Permited for stage contract Carriage/Public carrier: Other Truck/Tractor": [
                "Other Truck/Tractor"
            ],
            "Commercial Type Vehicles Permited for stage contract Carriage/Public carrier: Passenger Carrying Type": [
                "Capacity Upto 24 Passengers",
                "Exceeding 24 Passengers"
            ],
            "Compressors": [
                "Trailers with plant permanently (Endt. No. 42 must be used,0)",
                "Vehicle (Endt. No. 42 must be used,0)"
            ],
            "Cranes": [
                "Breakdown vehicles permanently fitted and used only as such",
                "Goods Carrying vehicles having a crane as a part of or fixed to the vehicle or trailer",
                "Mobile Cranes Excluding Damage caused to the unit by overturning during operational use as a tool of trade - Trailers",
                "Mobile Cranes Excluding Damage caused to the unit by overturning during operational use as a tool of trade - Vehicles",
                "Mobile Cranes Excluding Liability to the public Risks while in use as a tool of trade except - Trailers",
                "Mobile Cranes Excluding Liability to the public Risks while in use as a tool of trade except - Vehicles"
            ],
            "Delivery Trucks, Pedestrain Controlled": [
                "Delivery Trucks, Pedestrain Controlled"
            ],
            "Dispensaries": [
                "Trailer feeted as Mobile shops & Canteen  (Endt. no 45 must be used,0)",
                "Vehicles (Endt. no 45 must be used,0)"
            ],
            "Dragline Excavators": [
                "Use confined to own primises or concession (Endt. 61,44 & 43 must be used,0)",
                "Use not confined to own primises or concession"
            ],
            "Dumpers": [
                "Use confined to own premises or concession (Endt. no 61 must be used,0)",
                "Use not confined to own premises or concession (Endt. no 62 must be used,0)"
            ],
            "Dust, Water Carts Road Sweepers and Tower Wagons used for Overhead Mains Services": [
                "Vehicles"
            ],
            "Dust, Water Carts Road Sweepers and Tower Wagons used for Overhead Mains Services Trailers": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ]
            ,
            "Electric Trolleyes or Tractors": [
                "Trailers",
                "Vehicles"
            ],
            "Excavators": [
                "Use confined to own primises or concession (Endt. 61,44 & 43 must be used,0)",
                "Use not confined to own primises or concession"
            ],
            "Fire Brigade and Salvage Corps vehicles": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Vehicles"
            ],
            "Footpath Rollers": [
                "Exceeding 2.50 tons",
                "Not Exceeding 2.50 tons"
            ],
            "Fork-Lift Trucks": [
                "Trailers (Premium to be charged per Trailer,0)",
                "Vehicles"
            ],
            "Grabs": [
                "Use confined to own primises or concession (Endt. 61,44 & 43 must be used,0)",
                "Use not confined to own primises or concession"
            ],
            "Griting Machines": [
                "Exceeding 2.50 tons",
                "Not Exceeding 2.50 tons"
            ],
            "Hearses": [
                "na"
            ],
            "Horse Boxes": [
                "na"
            ],
            "Ladder Carrier Cars": [
                "na"
            ],
            "Lawn Movers": [
                "na"
            ],
            "Letourna Dozers (Use confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors (Endt. no 61 Must be used,0)"

            ],
            "Letourna Dozers (Use not confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors"
            ],
            "Levellers (Use confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors (Endt. no 61 Must be used,0)"
            ],
            "Levellers (Use not confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors"
            ],
            "Loaders": [
                "Hough Huff Pay Loader",
                "Loaders where actual Loader is Trailer (a,0)Tractor ",
                "Loaders where actual Loader is Trailer (b,0)Loader"
            ],
            "Mechanicals Navvies, Shovels, Grabs & Excavators": [
                "Use confined to own permises or concession (Endt. no 61 Must be used,0)",
                "Use not confined to own permises or concession (Endt. no 61,44,43 Must be used,0)"
            ],
            "Military Tea Vanes": [
                "Trailers (Endt. no 45 Must be used,0)",
                "Vehicles (Endt. no 45 Must be used,0)"
            ],
            "Milk Vans": [
                "Trailers with plant permanently attached (Towing 1 trailer only,0) (Endt. No 42 must be used,0)"
            ],
            "Milk Vans ( Insulated,0) Self-Propelled vehicles with plant permanently attached. Excluding Liability to the public Risks while in use as a tool of trade except as required by the Motor vehicles act. 1939 and Act, 1991": [
                "Vehicle (Endt. No 42 must be used,0)"
            ],
            "Mobile Shop and Canteens Excluding (a,0)Loss or damage to utensils and stock in trade (b,0)Liability arising from poisioning of any kind goods supplied and from any treatment given": [
                "Trailer fitted as Mobile Shops and Canteens (Endt. No 45 must be used,0)",
                "Vehicles (Endt. No 45 must be used,0)"
            ],
            "Mobile Surgeries and Dispensaries": [
                "Trailer fitted as Mobile Surgeries and Dispensaries",
                "Vehicles"
            ],
            "Oil and Petrol Transport Vehicles Registered under private carriers permit": [
                "Passenger Vehicles over 3000 CC or Goods carrying vehicles over 3 tons",
                "Passenger Vehicles Upto 1300 CC or Goods carrying vehicles upto 1/2 ton",
                "Passenger Vehicles Upto 1800 CC or Goods carrying vehicles upto 1-1.5 tons",
                "Passenger Vehicles Upto 3000 CC or Goods carrying vehicles upto 3 tons"
            ],
            "Oil and Petrol Transport Vehicles Registered under public carriers permit": [
                "Upto five Tons"
            ],
            "Postal Vans (a,0)vehicles used exclusively for the carriage of postal Mails and private motor vehicle policy form to be used (b,0)vehicles registered as private carriers used exclusively for the conveyance of postal employees vehicles used exclusively fo": [
                "Passenger Vehicles over 3000 CC or Goods carrying vehicles over 3 tons",
                "Passenger Vehicles Upto 1300 CC or Goods carrying vehicles upto 1/2 ton",
                "Passenger Vehicles Upto 1800 CC or Goods carrying vehicles upto 1-1.5 tons",
                "Passenger Vehicles Upto 3000 CC or Goods carrying vehicles upto 3 tons"
            ],
            "Prison Vans": [
                "na"
            ],
            "Refuse Carts": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Rippers (Use confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors (Endt. no 61 Must be used,0)"
            ],
            "Rippers (Use not confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors"
            ],
            "Road Rollers": [
                "Exceeding 2.50 Tons",
                "Not Exceeding 2.50 Tons"
            ],
            "Road Sweepers": [
                "na"
            ],
            "Scrapers": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"

            ],
            "Sheep Foot Tamping Rollers": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Shovels": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Site Clearing & Levelling Plant Use confined to own premises or concession": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Site Clearing & Levelling Plant Use confined to own premises or concession (a,0) Tractors": [
                "Site Clearing & Levelling Plant",
                "Tractors (Endt. No. 61 must be used,0)"
            ],
            "Site Clearing & Levelling Plant Use Not confined to own premises or concession": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Site Clearing & Levelling Plant Use Not confined to own premises or concession (a,0) Tractors": [
                "Tractors"
            ],
            "Spraying Plant": [
                "Agricultural Tractors Designed primarily Pedestrain Controlled and not exceeding 6 H.P.",
                "Excluding Vehicles owned by Timber Marchants and Haulers tree haulage which must be rated as Goods carrying Vehicles-Own Goods or general Cartage - Use confined to insureds farm or Concession expect as provided by Endosment No. 61",
                "Excluding Vehicles owned by Timber Marchants and Haulers tree haulage which must be rated as Goods carrying Vehicles-Own Goods or general Cartage - Use not confined to insureds farm or Concession"
            ],
            "Spraying Plant (Tar Sprayers,0)": [
                "Tractors",
                "Vehicles"
            ],
            "Spraying Plant Other Sprayers": [
                "Tractors",
                "Vehicles (Endt. No 42 must be used,0)"
            ],
            "Tankers": [
                "Upto 5 tons",
                "Upto 6 Tons",
                "Upto 7 Tons",
                "Upto 8 Tons",
                "Upto 9 Tons",
                "Upto 10 Tons"
            ],
            "Tar Sprayers": [
                "Trailers",
                "Vehicles"
            ],
            "Tower Wagons-Traction Engines": [
                "na"
            ],
            "Tractors": [
                "Agricultural Tractors Designed primarily Pedestrain Controlled and not exceeding 6 H.P.",
                "Excluding Vehicles owned by Timber Marchants and Haulers tree haulage which must be rated as Goods carrying Vehicles-Own Goods or general Cartage - Use confined to insureds farm or Concession expect as provided by Endosment No. 61",
                "Excluding Vehicles owned by Timber Marchants and Haulers tree haulage which must be rated as Goods carrying Vehicles-Own Goods or general Cartage - Use not confined to insureds farm or Concession",
                "Goods Carrying Tractors not constructed for general raod use",
                "Tractors used with one or more of the following attachments : Anglodozers, Bulldozers, Levellers, Rippers, Scrapers, Sheep Foot Tamping Rollers, Trail Builders and Treedozers"
            ],
            "Tractors and traction Engines Hauling Trailers and used as Haulage contractors goods carrying Vehicles": [
                "Tractor Portion Only (Endt. no 75 must be used,0)"
            ],
            "Tractors and traction Engines Hauling Trailers and used as Haulage contractors goods carrying Vehicles - Trailers to be towed by it (Endt. no 75 must be used,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)"
            ],
            "Tractors and traction Engines Hauling Trailers and used for the carriage of insureds own goods, registered for general road use - Tractor portion only": [
                "Passenger Vehicles over 3000 CC or Goods carrying vehicles over 3 tons",
                "Passenger Vehicles Upto 1300 CC or Goods carrying vehicles upto 1/2 ton",
                "Passenger Vehicles Upto 1800 CC or Goods carrying vehicles upto 1-1.5 tons",
                "Passenger Vehicles Upto 3000 CC or Goods carrying vehicles upto 3 tons"
            ],
            "Tractors and traction Engines Hauling Trailers and used for the carriage of insureds own goods, registered for general road use - Trailers to be towed by it": [
                "Passenger Vehicles over 3000 CC or Goods carrying vehicles over 3 tons",
                "Passenger Vehicles Upto 1300 CC or Goods carrying vehicles upto 1/2 ton",
                "Passenger Vehicles Upto 1800 CC or Goods carrying vehicles upto 1-1.5 tons",
                "Passenger Vehicles Upto 3000 CC or Goods carrying vehicles upto 3 tons"
            ],
            "Trail Builders (Use confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors (Endt. no 61 Must be used,0)"
            ],
            "Trail Builders (Use not confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors"
            ],
            "Tree Dozers (Use confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors (Endt. no 61 Must be used,0)"
            ],
            "Tree Dozers (Use not confined to own premises or concession,0)": [
                "Towing of not more than two trailers at a time Agricultural & Foresty Vehicles Item",
                "Towing of not more than two trailers at a time carrige of good for hire or reward",
                "Towing of one trailer only Agricultural & Foresty Vehicles Item",
                "Towing of one trailer only carrige of good for hire or reward",
                "Towing of three or more trailers at a time Agricultural & Foresty Vehicles Item (To be rated by the comittee on application,0)",
                "Towing of three or more trailers at a time carrige of good for hire or reward (To be rated by the comittee on application,0)",
                "Tractors"
            ],
            "Trolleyes and Goods Carrying Tractors - Not constructed for general road use Lifting apparatuses is included without additional premium": [
                "Trailers (Endt. No 75 must be used,0)",
                "Veicles"
            ],
            "Water Carts": [
                "na"
            ],
            "Welding Plant": [
                "Trailers",
                "Vehicle"
            ],
            "X-Ray Vehicles": [
                "Trailer fitted as Mobile shops and canteens (Endt. No 45 must be used,0)",
                "Vehicles (Endt. No 45 must be used,0)"
            ]
        },
    }
} as const;

// tariffType
// groupOfVehicle
// typeOfVehicle
// category
