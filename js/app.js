
var unknown, known, vulndb, cve;
var unknown_extract, known_extract, vulndb_extract, cve_extract;

var sel_back = "#bcbddc";
var curr_sel = "cve";

function sel_unknown(d, i) {
  curr_sel = "unknown";
  unknown_box.style("background", sel_back);
  all_box.style("background", sel_back);
  vuln_box.style("background", sel_back);
  cve_box.style("background", sel_back);
  updateSim(unknown);
  d3.event.stopPropagation();
}

function sel_all(d, i) {
  curr_sel = "known";
  unknown_box.style("background", "white");
  all_box.style("background", sel_back);
  vuln_box.style("background", sel_back);
  cve_box.style("background", sel_back);
  updateSim(known);
  d3.event.stopPropagation();
}

function sel_vuln(d, i) {
  curr_sel = "vulndb";
  unknown_box.style("background", "white");
  all_box.style("background", "white");
  vuln_box.style("background", sel_back);
  cve_box.style("background", sel_back);
  updateSim(vulndb);
  d3.event.stopPropagation();
}

function sel_cve(d, i) {
  curr_sel = "cve";
  unknown_box.style("background", "white");
  all_box.style("background", "white");
  vuln_box.style("background", "white");
  cve_box.style("background", sel_back);
  updateSim(cve);
  d3.event.stopPropagation();
}

function justCrit() {
  if (curr_sel == "cve") updateSim(cve);
  if (curr_sel == "vulndb") updateSim(vulndb);
  if (curr_sel == "known") updateSim(known);
  if (curr_sel == "unknown") updateSim(unknown);
}

var unknown_box = d3.select("#unknown").on("click", sel_unknown);
var all_box = d3.select("#all").on("click", sel_all);
var vuln_box = d3.select("#vulndb").on("click", sel_vuln);
var cve_box = d3.select("#cve").on("click", sel_cve);
var just_crit = d3.select("#justcrit").on("change", justCrit);

var width=800, height=600;
var div = d3.select("#vis");
var svg = div.append("svg").attr("width", width).attr("height", height);
var scale_fill_score = d3.scaleOrdinal()
                         .domain(['0-1', '1-2', '2-3', '3-4', '4-5',
                                  '5-6', '6-7', '7-8', '8-9', '9-10'])
                         .range(["#00c402", "#00e021", "#00f003", "#d0ff04", "#ffe003",
                                 "#ffcc03", "#ffbc12", "#ff9c21", "#ff8002", "#ff0201"]);


var bars_width = 195, bars_height = 80;

var x = d3.scaleBand().range([0, bars_width]).padding(0.1);
var y = d3.scaleLinear().range([bars_height, 0]);

var f_svg = d3.select("#f_svg").append("g").attr("transform", "translate(1,1)");
var o_svg = d3.select("#o_svg").append("g").attr("transform", "translate(1,1)");
var m_svg = d3.select("#m_svg").append("g").attr("transform", "translate(1,1)");
var i_svg = d3.select("#i_svg").append("g").attr("transform", "translate(1,1)");
var e_svg = d3.select("#e_svg").append("g").attr("transform", "translate(1,1)");

function updateBars() {

  var dat;

  if (curr_sel == "cve") dat = cve_extract;
  if (curr_sel == "vulndb") dat = vulndb_extract;
  if (curr_sel == "known") dat = known_extract;
  if (curr_sel == "unknown") dat = unknown_extract;

  var x1 = x.domain(['0-1', '1-2', '2-3', '3-4', '4-5', '5-6', '6-7', '7-8', '8-9', '9-10']);
  var y1 = y.domain([0, dat.max_val]);

  var ent_df = dat.enterprise;
  var for_df = dat.foreign;
  var oss_df = dat.oss;
  var ics_df = dat.ics;
  var med_df = dat.medical;

//  if (just_crit.property("checked")) {
//    ent_df = ent_df.filter(d => d.score == '9-10');
//    for_df = for_df.filter(d => d.score == '9-10');
//    oss_df = oss_df.filter(d => d.score == '9-10');
//    ics_df = ics_df.filter(d => d.score == '9-10');
//    med_df = med_df.filter(d => d.score == '9-10');
//    x1 = x.domain(['9-10']);
//  }

  var e1 = e_svg.selectAll(".bar").data(ent_df);
  var f1 = f_svg.selectAll(".bar").data(for_df);
  var o1 = o_svg.selectAll(".bar").data(oss_df);
  var i1 = i_svg.selectAll(".bar").data(ics_df);
  var m1 = m_svg.selectAll(".bar").data(med_df);

  e1.attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  e1.enter().append("rect")
    .attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  f1.attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  f1.enter().append("rect")
    .attr("class", "bar")
    .attr("x", d => x(d.score))
    .attr("width", x.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  o1.attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  o1.enter().append("rect")
    .attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  m1.attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  m1.enter().append("rect")
    .attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  i1.attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

  i1.enter().append("rect")
    .attr("class", "bar")
    .attr("x", d => x1(d.score))
    .attr("width", x1.bandwidth())
    .attr("y", d => y1(d.n))
    .attr("fill", d => scale_fill_score(d.score))
    .attr("height", d => (height - y1(d.n)));

//  e1.remove();
//  f1.remove();
//  o1.remove();
//  m1.remove();
//  i1.remove();

}

var node_g = svg.append("g").attr("class", "nodes");
var t = d3.transition().duration(100);

var vis_nodes ;
var clear_nodes = [];
var simulation = d3.forceSimulation()
                   .nodes(clear_nodes)
                   .alphaTarget(0)
                   .alpha(1)
                   .alphaMin(0.001)
                   .alphaDecay(1 - Math.pow(0.001, 1 / 300))
                   .velocityDecay(0.4)
                   .force("charge", d3.forceManyBody().strength(-10))
                   .force("center", d3.forceCenter(400, 300))
                   .force("link", d3.forceLink(clear_nodes))
                   .force("x", d3.forceX(0))
                   .force("y", d3.forceY(0));

function updateSim(vuln_nodes) {

  simulation.stop();
  simulation.force(d3.forceLink(clear_nodes));
  simulation.nodes(clear_nodes);
  simulation.restart();

  var vis_nodes = vuln_nodes;
  if (just_crit.property("checked")) vis_nodes = vis_nodes.filter(d => d.s == '9-10');
  vis_nodes = vis_nodes.sort((a, b) => a.s.localeCompare(b.s));

  node_g.transition(t).attr('opacity', 0).on('end', function() {

    var node = node_g.selectAll("circle").remove();

    node_g.remove();
    node_g = svg.append("g").attr("class", "nodes");

    node_g.attr("opacity", 1);

    node = node_g.selectAll("circle").data(vis_nodes).enter().append("circle")
         .attr('stroke', "#b2b2b2")
         .attr('stroke-width', 1)
         .attr('fill', d => scale_fill_score(d.s))
         .attr("opacity", 1)
         .attr('fill-opacity', 1)
         .attr("r", 7)
         .merge(node);

    var ticked = function() { node.attr("cx", d => d.x).attr("cy", d => d.y); };

    simulation.on("tick", ticked);
    simulation.force("link").links(clear_nodes);
    simulation.nodes(vis_nodes);
    simulation.alphaTarget(0);
    simulation.alpha(1);
    simulation.alphaMin(0.001);
    simulation.alphaDecay(1 - Math.pow(0.001, 1 / 300));
    simulation.velocityDecay(0.4);

    simulation.restart();

    updateBars();

  });

}

function startSim(error, unknown_d, known_d, vulndb_d, cve_d, u_e, k_e, v_e, c_e) {

  unknown = unknown_d;
  known = known_d;
  vulndb = vulndb_d,
  cve = cve_d;

  unknown_extract = u_e;
  known_extract = k_e;
  vulndb_extract = v_e;
  cve_extract = c_e;

  cve_box.style("background", sel_back);

  updateSim(cve_d);

}

d3.queue()
  .defer(d3.json, "json/unknown.json")
  .defer(d3.json, "json/all.json")
  .defer(d3.json, "json/vulndb.json")
  .defer(d3.json, "json/cve.json")
  .defer(d3.json, "json/unknown_extract.json")
  .defer(d3.json, "json/all_extract.json")
  .defer(d3.json, "json/vulndb_extract.json")
  .defer(d3.json, "json/cve_extract.json")
  .await(startSim);

