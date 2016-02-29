package portsbinding

import (
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack/networking/v2/ports"
)

type CreateOptsExt struct {
	ports.CreateOptsBuilder
	HostID   string
	VNICType string
	Profile  map[string]string
}

// Get retrieves a specific port based on its unique ID.
func Get(c *gophercloud.ServiceClient, id string) GetResult {
	var res GetResult
	_, res.Err = c.Get(getURL(c, id), &res.Body, nil)
	return res
}

// ToPortCreateMap casts a CreateOptsExt struct to a map.
func (opts CreateOptsExt) ToPortCreateMap() (map[string]interface{}, error) {
	p, err := opts.CreateOptsBuilder.ToPortCreateMap()
	if err != nil {
		return nil, err
	}

	port := p["port"].(map[string]interface{})

	if opts.HostID != "" {
		port["binding:host_id"] = opts.HostID
	}
	if opts.VNICType != "" {
		port["binding:vnic_type"] = opts.VNICType
	}
	if opts.Profile != nil {
		port["binding:profile"] = opts.Profile
	}

	return map[string]interface{}{"port": port}, nil
}

// Create accepts a CreateOpts struct and creates a new network using the values
// provided. You must remember to provide a NetworkID value.
func Create(c *gophercloud.ServiceClient, opts ports.CreateOptsBuilder) CreateResult {
	var res CreateResult

	reqBody, err := opts.ToPortCreateMap()
	if err != nil {
		res.Err = err
		return res
	}

	_, res.Err = c.Post(createURL(c), reqBody, &res.Body, nil)
	return res
}

// UpdateOptsExt represents the attributes used when updating an existing port.
type UpdateOptsExt struct {
	ports.UpdateOptsBuilder
	HostID   string
	VNICType string
	Profile  map[string]string
}

// ToPortUpdateMap casts an UpdateOptsExt struct to a map.
func (opts UpdateOptsExt) ToPortUpdateMap() (map[string]interface{}, error) {
	p, err := opts.UpdateOptsBuilder.ToPortUpdateMap()
	if err != nil {
		return nil, err
	}

	port := p["port"].(map[string]interface{})

	if opts.HostID != "" {
		port["binding:host_id"] = opts.HostID
	}
	if opts.VNICType != "" {
		port["binding:vnic_type"] = opts.VNICType
	}
	if opts.Profile != nil {
		port["binding:profile"] = opts.Profile
	}

	return map[string]interface{}{"port": port}, nil
}

// Update accepts a UpdateOpts struct and updates an existing port using the
// values provided.
func Update(c *gophercloud.ServiceClient, id string, opts ports.UpdateOptsBuilder) UpdateResult {
	var res UpdateResult

	reqBody, err := opts.ToPortUpdateMap()
	if err != nil {
		res.Err = err
		return res
	}

	_, res.Err = c.Put(updateURL(c, id), reqBody, &res.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200, 201},
	})
	return res
}
