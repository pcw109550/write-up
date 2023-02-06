D = DiGraph(multiedges=True, sparse=True)

for i in range(5):
    D.add_edge((i % 5, (i + 1) % 5, "$f$"))

D.graphplot(vertex_size=750, edge_labels=True, talk=True).plot(figsize=(3, 3)).save("graph.png")
