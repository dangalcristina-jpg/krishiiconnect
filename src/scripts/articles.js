// Central article registry. To add a new article:
// 1. Add an object to ARTICLES below with a unique slug.
// 2. The slug determines the URL: /articles/<slug>
// 3. Include a heroImage, content sections, and tips.

export const ARTICLES = [
  {
    slug: 'best-rice-farming-practices',
    icon: '🌾',
    title: 'Best Rice Farming Practices',
    date: 'Jul 20, 2026',
    excerpt: 'Learn modern techniques to maximize your rice yield this season.',
    heroImage: 'https://images.pexels.com/photos/13517420/pexels-photo-13517420.jpeg?auto=compress&cs=tinysrgb&h=650&w=940',
    heroAlt: 'Terraced rice fields surrounded by lush greenery in Pokhara, Nepal',
    sections: [
      {
        heading: 'Land Preparation',
        body: 'Rice grows best in puddled, levelled fields that retain water and suppress weeds. Begin by ploughing the field two to three times at 10–15 day intervals, turning under any previous crop residue. After the first ploughing, apply well-decomposed farmyard manure (FYM) at 10–15 tons per hectare. puddle the field with a final shallow ploughing under standing water (2–5 cm), then level carefully. A perfectly level field ensures uniform water depth, even crop stand, and fewer weed pockets. In the Terai, where most Nepali rice is grown, aim to finish land preparation before the monsoon fully establishes so transplanting is not delayed.',
      },
      {
        heading: 'Seed Selection',
        body: 'Choose varieties suited to your agro-ecological zone and the season. For the Terai, popular choices include Hardinath-1, Sabitri, and Sama Mansuli for normal season, and Radha-4, Ramdhan, and Chandan Nath for late planting. In the hills and high hills, Khumal-4, Khumal-8, and Chandan Nath perform well. Always use certified seed from a reliable source, or save seed from a clean, disease-free previous crop. Before sowing, test germination — it should be above 80%. Clean seed reduces the risk of seed-borne diseases like blast, bacterial leaf blight, and false smut.',
      },
      {
        heading: 'Nursery and Seedling Management',
        body: 'Prepare a nursery bed near the main field on well-drained, fertile soil. Apply 25 g nitrogen, 25 g phosphorus, and 25 g potash per square metre of nursery. Sow pre-germinated seed at 40–50 kg per hectare of main field area. For wet-bed nurseries, soak seed for 24 hours and incubate for 24–36 hours until the radicle emerges. Keep the nursery moist but not flooded for the first few days, then maintain a thin film of water. Healthy seedlings are 20–25 days old, 20–30 cm tall, and have 3–4 leaves. Pull seedlings carefully to minimise root damage — this reduces transplanting shock and speeds recovery.',
      },
      {
        heading: 'Transplanting',
        body: 'Transplant 2–3 seedlings per hill at 20×15 cm or 25×15 cm spacing in the Terai. In the hills, slightly closer spacing (20×10 cm) can compensate for smaller hills. Plant shallow (3–4 cm deep) — deep planting delays tillering and reduces yield. Transplant within 30 minutes of pulling; if that is not possible, keep seedlings in shade with roots moist. Delayed transplanting beyond 30 days reduces yield by 1–2 percent per day. For direct-seeded rice, use a drum seeder on levelled, moist fields at 40–50 kg seed per hectare.',
      },
      {
        heading: 'Water Management',
        body: 'Maintain 2–5 cm of standing water for the first two weeks after transplanting to help seedlings establish. Thereafter, keep the field alternately wet and dry (AWD) — flood to 5 cm, let it drop to near saturation, then flood again. This saves water, encourages deeper roots, and reduces arsenic uptake. Drain the field completely 7–10 days before harvest to hasten maturity and make harvesting easier. Never let the field crack severely during the vegetative stage, as this damages roots and reduces tillering.',
      },
      {
        heading: 'Fertilizer Use',
        body: 'Apply a balanced dose based on a soil test where possible. A general recommendation for the Terai is 100:30:30 kg NPK per hectare. Apply all phosphorus and potash as basal, and split nitrogen into three doses: one-third basal, one-third at active tillering (20–25 DAT), and one-third at panicle initiation. Incorporate zinc sulphate at 25 kg per hectare if deficiency symptoms (brown spots on older leaves) appear. Top-dress urea into standing water and avoid applying before heavy rain, which causes nitrogen loss through runoff.',
      },
      {
        heading: 'Pest and Disease Management',
        body: 'Rice blast is the most destructive disease in Nepal. Plant resistant varieties where available, avoid excess nitrogen, and if blast appears, spray tricyclazole 0.4 g per litre at booting and heading. Bacterial leaf blight worsens after storms and flooding — drain and re-flood, and avoid wounding plants. For brown plant hopper and stem borer, use light traps, maintain field sanitation, and apply buprofezin or cartap if populations exceed economic thresholds. Avoid blanket insecticide sprays that kill natural enemies like spiders and dragonflies, which keep pest populations in check.',
      },
      {
        heading: 'Harvesting',
        body: 'Harvest when 80–85 percent of grains are straw-coloured and the rest are still slightly green. Delaying harvest beyond this stage causes shattering losses and grain cracking. Cut the crop at 10–15 cm above the ground, thresh within 2–3 days, and dry grain to 12–14 percent moisture before storage. Use a mechanical thresher where available to reduce labour and grain loss. Avoid sun-drying on bare concrete above 50°C, as rapid drying causes fissures and broken grains.',
      },
    ],
    tips: [
      'Use certified, disease-free seed every season — it is the cheapest yield insurance you can buy.',
      'Level your field with a laser leveller if possible; uneven fields waste water and fertiliser.',
      'Split nitrogen into three applications to match the crop\'s demand and reduce losses.',
      'Drain the field 7–10 days before harvest to speed maturity and reduce lodging.',
      'Rotate rice with a pulse or oilseed crop to break pest cycles and restore soil fertility.',
    ],
  },
  {
    slug: 'vegetable-storage-tips',
    icon: '🥬',
    title: 'Vegetable Storage Tips',
    date: 'Jul 15, 2026',
    excerpt: 'Keep your vegetables fresh longer with these simple storage methods.',
    heroImage: 'https://images.pexels.com/photos/6654138/pexels-photo-6654138.jpeg?auto=compress&cs=tinysrgb&h=650&w=940',
    heroAlt: 'A vibrant assortment of fruits and vegetables on a kitchen rack',
    sections: [
      {
        heading: 'Proper Harvesting',
        body: 'Post-harvest losses begin in the field. Harvest vegetables during the cool early-morning hours when temperatures are lowest and the produce is most turgid. Avoid harvesting during or immediately after rain — wet produce rots faster and spreads disease. Use clean, sharp tools to make clean cuts; bruised tissue is the entry point for decay organisms. Handle produce gently — every bruise, scratch, or drop shortens shelf life. Sort out damaged, overripe, or diseased produce in the field itself so it does not contaminate the good lot during transport and storage.',
      },
      {
        heading: 'Cleaning and Sorting',
        body: 'Remove field heat as quickly as possible after harvest — this is the single most effective step to preserve quality. If you have access to cold water or a shaded, ventilated area, use it. Gently brush off soil rather than washing, since washing adds moisture that encourages rot. If washing is necessary, use clean, chlorinated water (150 ppm free chlorine) and dry the produce thoroughly before packing. Sort by size and ripeness — mixing overripe with unripe produce causes the whole lot to ripen and spoil faster due to ethylene.',
      },
      {
        heading: 'Temperature and Humidity',
        body: 'Most vegetables lose quality rapidly above 25°C. Cool storage at 0–10°C dramatically extends shelf life, but not all vegetables tolerate cold. Leafy greens, broccoli, cabbage, and root crops prefer 0–4°C with high humidity (90–95 percent). Tomatoes, peppers, cucumbers, and eggplants prefer 10–15°C — below 10°C they suffer chilling injury (pitting, water-soaked spots, and rot). Onions and garlic need dry, cool (0–5°C) conditions with low humidity (60–70 percent). Potatoes store best at 4–10°C in the dark to prevent sprouting and greening.',
      },
      {
        heading: 'Storage Methods',
        body: 'For small-scale farmers without cold storage, use evaporative cooling: a double-walled brick or earthen chamber with wet sand between the walls can maintain 15–20°C below ambient. Zero-energy cool chambers made from brick and wet sand can extend the shelf life of leafy vegetables by 3–5 days. For root crops, store in well-ventilated crates or pits lined with dry straw. Onions and garlic should be cured (dried) for 7–10 days in the shade with good airflow before storage, then hung in mesh bags or stored on slatted shelves. Never store onions and potatoes together — onions release gases that cause potatoes to sprout and spoil.',
      },
      {
        heading: 'Preventing Spoilage',
        body: 'Inspect stored produce every 2–3 days and remove anything showing soft rot, mould, or shrivelling — one rotten item can spoil an entire crate. Maintain good ventilation in the storage room; still, humid air encourages fungal growth. Keep storage areas clean and disinfected between batches. For longer-term storage, consider simple processing: pickling, drying, or fermentation can preserve surplus vegetables for months and add value. Solar drying of tomatoes, chillies, and leafy greens is practical in Nepal\'s dry season and requires no equipment beyond a clean drying surface and sunlight.',
      },
      {
        heading: 'Which Vegetables to Refrigerate',
        body: 'Refrigerate (0–10°C): leafy greens, broccoli, cauliflower, cabbage, carrots, radishes, beans, peas, and sweet corn. Do not refrigerate (store cool and dry, 10–15°C): tomatoes, cucumbers, peppers, eggplants, pumpkins, and unripe bananas. Never refrigerate: onions, garlic, potatoes, and sweet potatoes — cold temperatures convert their starches to sugars, changing flavour and texture and promoting rot. Store tomatoes at room temperature until fully ripe, then use immediately or process.',
      },
      {
        heading: 'Reducing Post-Harvest Losses',
        body: 'In Nepal, post-harvest losses for vegetables can reach 25–40 percent, mostly due to poor handling, lack of cold chain, and delayed transport. Farmers can reduce losses by harvesting at the right maturity, pre-cooling, sorting, and using proper packaging — stackable, ventilated plastic crates protect far better than jute sacks. Plan harvests to match market days so produce reaches the consumer quickly. Forming farmer groups to share transport and storage infrastructure spreads the cost and improves bargaining power. Even small investments in shade, ventilation, and gentle handling can cut losses in half.',
      },
    ],
    tips: [
      'Harvest in the cool early morning and remove field heat as quickly as possible.',
      'Never store onions and potatoes together — one makes the other spoil faster.',
      'Sort out damaged produce in the field; one rotten item ruins the whole crate.',
      'Use ventilated plastic crates instead of jute sacks to protect produce in transit.',
      'An evaporative cool chamber can extend leafy vegetable shelf life by 3–5 days with no electricity.',
    ],
  },
  {
    slug: 'seasonal-crop-guide',
    icon: '📅',
    title: 'Seasonal Crop Guide',
    date: 'Jul 10, 2026',
    excerpt: 'What to plant and when — a month-by-month guide for Nepali farmers.',
    heroImage: 'https://images.pexels.com/photos/8846150/pexels-photo-8846150.jpeg?auto=compress&cs=tinysrgb&h=650&w=940',
    heroAlt: 'Expansive farmland with young crops under a vibrant sky',
    sections: [
      {
        heading: 'Spring (February–April)',
        body: 'Spring in Nepal brings warming temperatures and pre-monsoon showers, making it ideal for planting heat-loving crops. In the Terai and lower hills, sow maize (for grain and fodder), spring rice, cucumbers, pumpkins, bottle gourd, bitter gourd, and watermelon. In the mid-hills, prepare nurseries for spring rice and transplant winter vegetables. This is also the time to plant potatoes in the high hills where the ground has just thawed. Apply compost before sowing and ensure irrigation is available — spring rainfall can be erratic.',
      },
      {
        heading: 'Summer / Monsoon (June–August)',
        body: 'The monsoon is the main cropping season. Transplant main-season rice in the Terai from late June to mid-July. In the hills, transplant rice from June to early August depending on elevation. This is also the time to sow rainfed maize, soybean, black gram, and finger millet (kodo). Vegetables suited to the monsoon include taro, yam, amaranth, and ridge gourd, which tolerate heavy rainfall. Ensure drainage channels are clear before the rains arrive — waterlogging kills young seedlings and spreads disease. In the high hills, plant buckwheat and naked barley.',
      },
      {
        heading: 'Autumn (September–November)',
        body: 'As the monsoon retreats, temperatures drop and humidity falls — excellent conditions for a wide range of crops. This is the prime season for planting cole crops: cabbage, cauliflower, broccoli, and radish. Sow mustard for oilseed, lentils, chickpeas, and wheat in the Terai from late October to November. Plant garlic and onions (bulb) in October–November for harvest the following spring. In the hills, this is the time to plant peas, broad beans, and winter potatoes. The cooler weather also reduces pest pressure, making autumn a high-quality, high-yield season for vegetables.',
      },
      {
        heading: 'Winter (December–January)',
        body: 'Winter is the coldest and driest season. In the Terai, wheat sown in November is in its vegetative stage and needs one or two irrigations. Mustard and lentil crops also need moisture — irrigate if winter rains fail. This is the season to grow leafy vegetables like spinach, mustard greens, coriander, and fenugreek, which tolerate cold. In frost-prone areas, protect young seedlings with plastic tunnels or mulch. In the high hills, most fields are under fallow or winter wheat. Use this quieter season to repair irrigation channels, prepare compost, and plan the coming year\'s crop rotation.',
      },
      {
        heading: 'Crop Selection by Region',
        body: 'Nepal\'s three ecological zones call for different strategies. The Terai (60–300 m) supports two rice crops a year (spring and monsoon), plus wheat, mustard, and lentils in winter, and maize and vegetables in spring. The mid-hills (300–2,000 m) grow one rice crop in the monsoon, maize in spring, and millet, wheat, mustard, and potatoes in winter. The high hills (above 2,000 m) have a short growing season — focus on cold-tolerant crops like buckwheat, naked barley, potatoes, apples, and off-season vegetables that fetch premium prices in lowland markets.',
      },
      {
        heading: 'General Planting Guidance',
        body: 'Match the crop to the season, the soil, and your market. Rotate crops to break pest and disease cycles — never plant the same crop family in the same field two seasons in a row. Use raised beds for vegetables in the monsoon to improve drainage. Apply compost before each crop and supplement with fertiliser based on soil test results. Stagger plantings by 1–2 weeks to spread harvest and reduce market gluts. Save your own seed from the best-performing plants to adapt varieties to your farm over time.',
      },
    ],
    tips: [
      'Clear drainage channels before the monsoon — waterlogging kills young seedlings.',
      'Rotate crop families every season to break pest and disease cycles.',
      'Use raised beds for monsoon vegetables to improve drainage.',
      'Stagger plantings by 1–2 weeks to spread harvest and avoid market gluts.',
      'Save seed from your best plants to adapt varieties to your farm over time.',
    ],
  },
  {
    slug: 'organic-farming-benefits',
    icon: '🌱',
    title: 'Organic Farming Benefits',
    date: 'Jul 5, 2026',
    excerpt: 'Why organic farming is better for your soil and your income.',
    heroImage: 'https://images.pexels.com/photos/28214180/pexels-photo-28214180.jpeg?auto=compress&cs=tinysrgb&h=650&w=940',
    heroAlt: 'Pile of organic compost with various plant roots and leaves',
    sections: [
      {
        heading: 'What Organic Farming Means',
        body: 'Organic farming is a system that relies on natural inputs and ecological processes rather than synthetic fertilisers and pesticides. It builds soil health through compost, green manures, and crop rotation; manages pests through biological control and resistant varieties; and avoids genetically modified seeds and synthetic growth regulators. In Nepal, organic farming has deep roots — traditional farming was largely organic until chemical inputs became widely available in the 1970s. Today, organic produce commands premium prices in domestic and export markets, making it both an ecological and economic choice.',
      },
      {
        heading: 'Soil Health',
        body: 'Healthy soil is the foundation of organic farming. Synthetic fertilisers feed the plant directly but degrade the soil over time — they reduce organic matter, kill beneficial microbes, and cause compaction. Organic practices build soil organic matter (SOM) through compost, cover crops, and reduced tillage. Higher SOM improves water retention, aeration, and nutrient availability, making crops more resilient to drought and disease. Test your soil every 2–3 years to track pH, organic matter, and nutrient levels. A well-managed organic soil can sustain yields indefinitely, while a chemically farmed soil often needs ever-increasing inputs to maintain the same output.',
      },
      {
        heading: 'Compost and Organic Manure',
        body: 'Compost is the cornerstone of organic nutrient management. Make compost from farmyard manure, crop residue, kitchen waste, and green material in a pit or heap with regular turning. Well-made compost is rich in stable organic matter, contains all major and micronutrients, and improves soil structure. Apply 10–20 tons per hectare as a basal dose before each crop. Supplement with green manures — sun hemp (Sunnhemp), dhaincha, or Sesbania — grown for 45–60 days and incorporated before flowering. For nitrogen, use vermicompost (richer and faster-acting than regular compost) or biofertilisers like Rhizobium for legumes and Azotobacter for non-legumes.',
      },
      {
        heading: 'Natural Pest Management',
        body: 'Organic pest management starts with prevention: healthy soil, resistant varieties, proper spacing, and crop rotation. Encourage natural enemies — spiders, ladybirds, lacewings, and dragonflies — by maintaining habitat diversity and avoiding all broad-spectrum sprays. For specific pests, use botanical pesticides: neem oil (azadirachtin) at 2–5 ml per litre for a wide range of pests; Bacillus thuringiensis (Bt) for caterpillars; and pheromone traps for fruit flies and stem borers. For fungal diseases, use Trichoderma-based biofungicides as seed treatment and soil application. Physical barriers like netting and light traps are effective and leave no residues.',
      },
      {
        heading: 'Benefits for Farmers',
        body: 'Organic farming reduces input costs — farmers save on chemical fertilisers and pesticides, which are among the most expensive inputs. Premium markets in Kathmandu, Pokhara, and export destinations pay 20–50 percent more for certified organic produce. Organic soils retain water better, reducing irrigation needs and drought risk. Farmers report fewer health problems from not handling toxic chemicals. Diversified organic systems — mixing grains, vegetables, legumes, and livestock — spread risk and provide year-round income. In Nepal, organic coffee, tea, ginger, and vegetables have established export markets with strong demand.',
      },
      {
        heading: 'Challenges',
        body: 'Transitioning to organic is not without difficulty. During the first 2–3 years, yields often drop as the soil ecosystem rebuilds — this is the "conversion period." Pest pressure can spike before natural enemy populations establish. Nutrient availability from organic sources is slower and less predictable than from synthetic fertilisers. Certification costs and paperwork can be a barrier for smallholders. Marketing requires effort — farmers must find buyers willing to pay the premium and build trust. Not all crops or regions are equally suited to organic; high-value, low-volume crops like coffee, tea, and vegetables are more profitable than staple grains.',
      },
      {
        heading: 'Practical Steps for Transitioning',
        body: 'Start small — convert one field or one crop to organic while keeping the rest conventional, so you learn without risking your whole income. Begin with composting: every farm can make compost from available materials at near-zero cost. Introduce a legume (peas, beans, lentils) into your rotation to add nitrogen naturally. Stop using broad-spectrum pesticides first — this allows natural enemies to recover and often solves pest problems without further intervention. Gradually reduce synthetic fertiliser over 2–3 years while building soil organic matter. If you plan to certify, start recording all inputs and practices from day one. Join a farmer group for shared knowledge, bulk composting, and collective marketing.',
      },
    ],
    tips: [
      'Start small — convert one field first and learn before scaling up.',
      'Make compost from farmyard manure and crop residue at near-zero cost.',
      'Stop broad-spectrum pesticides first to let natural enemies recover.',
      'Introduce a legume into your rotation to add nitrogen naturally.',
      'Record all inputs and practices from day one if you plan to certify.',
    ],
  },
];

export function getArticle(slug) {
  return ARTICLES.find((a) => a.slug === slug) || null;
}

export function getRelatedArticles(slug, count = 3) {
  return ARTICLES.filter((a) => a.slug !== slug).slice(0, count);
}
